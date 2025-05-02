import os.path
import base64
import webbrowser # Importar el módulo webbrowser para capturar su error específico
import sys # Para leer desde stdin para la entrada manual del código
from email import message_from_bytes

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

def authenticate_user(flow):
    """Maneja el flujo de autenticación OAuth 2.0, intentando primero el servidor local,
       luego run_console, y recurriendo al flujo manual de consola si es necesario."""
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

def main():
    """Muestra el uso básico de la API de Gmail con detección automática de navegador
       y fallback manual a consola para autenticación. Obtiene correos recientes.
    """
    creds = None
    # El archivo token.json almacena los tokens de acceso y actualización del usuario, y se
    # crea automáticamente cuando el flujo de autorización se completa por primera
    # vez.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # Si no hay credenciales (válidas) disponibles, permitir que el usuario inicie sesión.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                print("Refrescando token de acceso...")
                creds.refresh(Request())
            except Exception as e:
                print(f"No se pudo refrescar el token: {e}. Re-ejecutando autenticación.")
                # Si falla el refresco, forzar la re-autenticación usando la función auxiliar
                if not os.path.exists('credentials.json'):
                     print("Error: credentials.json no encontrado. Por favor, descárgalo desde Google Cloud Console.")
                     return
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = authenticate_user(flow) # Usar la función auxiliar
        else:
            # Iniciar el flujo de autenticación usando la función auxiliar
            if not os.path.exists('credentials.json'):
                 print("Error: credentials.json no encontrado. Por favor, descárgalo desde Google Cloud Console.")
                 return
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = authenticate_user(flow) # Usar la función auxiliar

        # Guardar las credenciales para la próxima ejecución solo si la autenticación fue exitosa
        if creds:
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        else:
            print("La autenticación falló. Saliendo.")
            return # Salir si la autenticación falló

    # Proceder solo si las credenciales son válidas
    if not creds:
         print("No se pudieron obtener credenciales válidas. Saliendo.")
         return

    try:
        # Construir el servicio de Gmail
        print("Construyendo el servicio de Gmail...")
        service = build('gmail', 'v1', credentials=creds)

        # --- Obtener Correos Recientes de la Bandeja de Entrada ---
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
                # Obtener los detalles completos del mensaje (solo metadatos por eficiencia)
                message = service.users().messages().get(userId='me', id=msg_id, format='metadata').execute()

                payload = message.get('payload', {})
                headers = payload.get('headers', [])

                # Extraer cabeceras de Asunto, Remitente y Fecha
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'Sin Asunto')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Remitente Desconocido')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Fecha Desconocida')

                print(f"\n--- ID Correo: {msg_id} ---")
                print(f"  De: {sender}")
                print(f"  Asunto: {subject}")
                print(f"  Fecha: {date}")
                # print(f"  Snippet: {message.get('snippet', 'N/A')}") # Snippet es una parte corta del cuerpo del mensaje

                # --- Opcional: Obtener y Decodificar Cuerpo (si es necesario) ---
                # Descomenta abajo si necesitas el cuerpo del correo (cambia format='full' arriba)
                # if 'parts' in payload:
                #     parts = payload.get('parts', [])
                #     data = parts[0]['body']['data'] # Simplista: asume que la primera parte es texto plano
                #     data = data.replace("-","+").replace("_","/")
                #     decoded_data = base64.b64decode(data)
                #     print(f"  Cuerpo (primera parte):\n{decoded_data.decode('utf-8', errors='replace')[:200]}...") # Imprime los primeros 200 caracteres
                # elif 'body' in payload:
                #      data = payload['body'].get('data')
                #      if data:
                #          data = data.replace("-","+").replace("_","/")
                #          decoded_data = base64.b64decode(data)
                #          print(f"  Cuerpo:\n{decoded_data.decode('utf-8', errors='replace')[:200]}...") # Imprime los primeros 200 caracteres


    except HttpError as error:
        # TODO(developer) - Manejar errores de la API de Gmail.
        print(f'Ocurrió un error de la API: {error}')
    except Exception as e:
        print(f'Ocurrió un error inesperado: {e}')


if __name__ == '__main__':
    main()
