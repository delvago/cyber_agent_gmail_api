import os.path
import base64
import webbrowser # Manejo de errores
import sys # Para leer desde stdin para la entrada manual del código
#from email import message_from_bytes
from bs4 import BeautifulSoup, Comment # Para limpiar correos e identificar y eliminar comentarios HTML
import re # Para eliminar URLs y normalizar saltos de línea

# Asegurarse de que la librería 'requests' esté instalada: pip install requests
try:
    import requests
except ImportError:
    print("Error: La librería 'requests' es necesaria para el flujo manual de consola.")
    print("Por favor, instálala usando: pip install requests")
    sys.exit(1) # Salir si requests no está disponible

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Si modificas estos SCOPES, elimina el archivo token.json.
# Alcance para acceso de solo lectura a Gmail.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def clean_html_content(html_content):
    """
    Limpia el contenido HTML para extraer el texto visible. # Docstring original del usuario restaurado
    """
    if not html_content:
        return ""
    
    soup = BeautifulSoup(html_content, "html.parser")

    # Eliminar etiquetas de script y style
    for script_or_style in soup(["script", "style", "head", "meta", "link"]):
        script_or_style.decompose()

    # Eliminar comentarios HTML
    for comment_tag in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment_tag.extract() 

    # Reemplazar <br> con saltos de línea
    for br_tag in soup.find_all("br"):
        br_tag.replace_with("\n")

    # Obtener el texto
    text = soup.get_text(separator="\n", strip=True)

    # Normalizar múltiples saltos de línea y eliminar líneas vacías
    lines = [line for line in text.splitlines() if line.strip()] # Procesa las líneas para eliminar las vacías
    cleaned_text_html = "\n".join(lines) # Une las líneas limpias con un solo salto de línea
    
    # Eliminar URLs usando expresiones regulares
    # Esta expresión regular busca patrones comunes de URL (http, https, ftp, www)
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+|www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    cleaned_text_no_urls = re.sub(url_pattern, '', cleaned_text_html) # Elimina las URLs encontradas
    
    # Re-procesar líneas después de la eliminación de URLs para asegurar que todas las líneas vacías (o que quedaron vacías después del strip) se eliminen,
    # y luego colapsar múltiples saltos de línea que pudieran persistir.
    lines_after_url_removal = [line.strip() for line in cleaned_text_no_urls.splitlines()] # Divide en líneas y quita espacios en blanco de cada una
    non_empty_lines_after_url_removal = [line for line in lines_after_url_removal if line] # Filtra las líneas que quedaron completamente vacías (después de strip)
    text_reassembled = "\n".join(non_empty_lines_after_url_removal) # Vuelve a unir con un solo salto de línea
    
    # Colapso final de múltiples saltos de línea (aunque el paso anterior debería manejar la mayoría de los casos)
    # y eliminar cualquier espacio en blanco al inicio o final de todo el texto.
    cleaned_text_final = re.sub(r'\n{2,}', '\n', text_reassembled).strip() 
    
    return cleaned_text_final # Devuelve el texto procesado, sin URLs y con saltos de línea normalizados


def authenticate_user(flow):
    """
    Maneja el flujo de autenticación OAuth 2.0, intentando primero el servidor local,
    luego run_console, y recurriendo al flujo manual de consola si es necesario.
    
    Args:
        flow: Flujo de autenticación de InstalledAppFlow de Google.
    Returns:
        creds: Credenciales de usuario autenticadas o None si falla la autenticación.
    """
    creds = None
    try:
        # Intentar primero el flujo del servidor local (abre un navegador)
        print("Intentando autenticación basada en explorador...")
        creds = flow.run_local_server(port=0)
    except webbrowser.Error as e:
        # Si ocurre webbrowser.Error, recurrir al flujo de consola
        print(f"No se pudo abrir un explorador ({e}). Solicitando autenticación por consola.")
        try:
            # Intentar el flujo de consola estándar
            print("Intentando autenticación estándar por consola (run_console)...")
            creds = flow.run_console()
        except AttributeError:
            # Recurrir al flujo manual de consola si run_console no existe (muy inusual)
            print("AttributeError: run_console() no encontrado. Recurriendo al flujo manual de consola.")
            # Obtener la URL de autorización
            auth_url, _ = flow.authorization_url(prompt='consent')
            print('Por favor, visita esta URL para autorizar esta aplicación:')
            print(auth_url)
            # Obtener el código de autorización del usuario
            code = input('Introduce el código de autorización: ')
            try:
                # Intercambiar el código por credenciales
                flow.fetch_token(code=code)
                creds = flow.credentials
            except Exception as fetch_error:
                print(f"Error al obtener el token con el código proporcionado: {fetch_error}")
                creds = None # Asegurarse de que creds sea None si falla la obtención
        except Exception as console_auth_error:
            print(f"Ocurrió un error durante la autenticación estándar por consola: {console_auth_error}")
            creds = None
    except Exception as e:
        # Capturar otras posibles excepciones durante la autenticación
        print(f"Ocurrió un error inesperado durante la autenticación: {e}")
        creds = None # Asegurarse de que creds sea None si falla la autenticación
    return creds

def get_email_body(payload):
    """
    Extrae el cuerpo de un correo electrónico del payload.
    Busca primero 'text/plain', luego 'text/html'.
    Devuelve el contenido decodificado o None si no se encuentra, junto con el tipo MIME.

    Args:
        payload: Respuesta de la API de Gmail que contiene el cuerpo del correo.

    Returns:
        body_content: El contenido del cuerpo del correo decodificado.
        mime_type_found: El tipo MIME encontrado ('text/plain' o 'text/html').
    """
    body_content = None
    mime_type_found = None
    
    preferred_mime_types = ['text/plain', 'text/html'] # Nueva lista para definir el orden de preferencia de los tipos MIME

    # Nueva función anidada para buscar recursivamente el cuerpo en las partes del mensaje
    def find_body_in_parts(parts_list):
        # Buscar los tipos MIME preferidos en el orden dado
        for MimeType in preferred_mime_types: # Itera sobre los tipos MIME preferidos
            for part in parts_list:
                if part.get('mimeType') == MimeType and 'data' in part.get('body', {}):
                    data = part['body']['data']
                    content = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='replace')
                    return content, MimeType
                # Revisar partes anidadas (ej. multipart/alternative dentro de multipart/mixed)
                elif 'parts' in part: # Si la parte actual tiene sub-partes, buscar recursivamente
                    nested_content, nested_mime = find_body_in_parts(part.get('parts', [])) # Llamada recursiva
                    if nested_content: # Si se encontró contenido en las partes anidadas
                        return nested_content, nested_mime
        return None, None # Si no se encuentra contenido en esta rama

    if 'parts' in payload:
        body_content, mime_type_found = find_body_in_parts(payload['parts']) # Llamada a la nueva función helper
    elif 'body' in payload and 'data' in payload['body']: # Mensaje no multipart, o una parte individual # Comentario original del usuario
        mime_type = payload.get('mimeType')
        if mime_type in preferred_mime_types: # Comprueba si el tipo MIME está entre los preferidos
            data = payload['body']['data']
            body_content = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8', errors='replace')
            mime_type_found = mime_type
            
    return body_content, mime_type_found


def main():
    """
    Uso básico de la API de Gmail con detección automática de navegador
    y fallback manual a consola para autenticación. Obtiene correos recientes.
    """
    creds = None
    # El archivo token.json almacena los tokens de acceso y actualización del usuario, y se
    # crea automáticamente cuando el flujo de autorización se completa por primera
    # vez. # Comentario original del usuario
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # Si no hay credenciales (válidas) disponibles, permitir que el usuario inicie sesión. # Comentario original del usuario
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                print("Refrescando token de acceso...")
                creds.refresh(Request())
            except Exception as e:
                print(f"No se pudo refrescar el token: {e}. Re-ejecutando autenticación.")
                creds = None # Nueva lógica: Forzar re-autenticación si el refresco falla
        
        if not creds: # Nuevo bloque: Si creds es None (falló el refresco o no existía token.json válido)
            if not os.path.exists('credentials.json'):
                print("Error: credentials.json no encontrado. Por favor, descárgalo desde Google Cloud Console.")
                return
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = authenticate_user(flow) # Usar la función auxiliar # Comentario original del usuario

        # Guardar las credenciales para la próxima ejecución solo si la autenticación fue exitosa # Comentario original del usuario
        if creds:
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        else:
            print("La autenticación falló. Saliendo.")
            return # Salir si la autenticación falló # Comentario original del usuario

    # Proceder solo si las credenciales son válidas # Comentario original del usuario
    if not creds:
        print("No se pudieron obtener credenciales válidas. Saliendo.")
        return

    try:
        # Construir el servicio de Gmail
        print("Construyendo el servicio de Gmail...")
        service = build('gmail', 'v1', credentials=creds)

        # --- Obtener Correos Recientes de la Bandeja de Entrada --- # Comentario original del usuario
        print("\nObteniendo correos recientes de INBOX...")
        # Llamar a la API de Gmail para obtener mensajes en INBOX, obtener máx 5 resultados
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=5).execute()
        messages = results.get('messages', [])

        if not messages:
            print("No se encontraron mensajes en INBOX.")
        else:
            print("Correos Recientes:")
            for message_info in messages:
                msg_id = message_info['id']
                # Obtener los detalles completos del mensaje
                message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

                payload = message.get('payload', {})
                headers = payload.get('headers', [])
                
                email_body, body_mime_type = get_email_body(payload) # Obtener el cuerpo del correo # Comentario original del usuario

                # Extraer cabeceras de Asunto, Remitente y Fecha # Comentario original del usuario
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'Sin Asunto')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Remitente Desconocido')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Fecha Desconocida')

                print(f"\n--- ID Correo: {msg_id} ---")
                print(f"  De: {sender}")
                print(f"  Asunto: {subject}")
                print(f"  Fecha: {date}")
                
                processed_body = ""
                if email_body:
                    # La función clean_html_content es robusta para texto plano real.
                    print(f"Limpiando cuerpo (MIME original: {body_mime_type if body_mime_type else 'Desconocido'})...") # Nueva línea de log
                    processed_body = clean_html_content(email_body)
                    
                    # Convertir a minúsculas y normalizar espacios (incluyendo saltos de línea a espacios)
                    text_for_llm_processing = " ".join(processed_body.lower().split()) # Nueva variable para el texto listo para LLM

                    print(f"  Cuerpo Procesado :\n{processed_body}")#Si se quiere el cuerpo completo procesado
                    #print(f"  Cuerpo Procesado (Primeros 500 caracteres):\n{processed_body[:500]}...") # Nueva línea de log con el cuerpo procesado
                    # print(f"  Texto para LLM (normalizado):\n{text_for_llm_processing[:200]}...") # Descomentar para ver el texto para LLM
                else:
                    print("  Cuerpo: No se encontró contenido de cuerpo en el mensaje.") # Comentario original del usuario
                    
                # El texto en 'processed_body' (limpio) o 'text_for_llm_processing' (normalizado para LLM) se usará para el procesamiento por LLM
                # (Comentario actualizado para reflejar las nuevas variables)

    except HttpError as error:
        # TODO(developer) - Manejar errores de la API de Gmail. # Comentario original del usuario
        print(f'Ocurrió un error de la API: {error}')
    except Exception as e:
        print(f'Ocurrió un error inesperado: {e}')


if __name__ == '__main__':
    main()
