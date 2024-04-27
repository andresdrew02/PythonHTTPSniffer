## Sniffer.py

### Descripción
Este script en Python 3, `sniffer.py`, utiliza diversas dependencias para realizar el análisis y filtrado del tráfico de red, centrándose en los paquetes HTTP. Permite al usuario seleccionar una interfaz de red específica o ingresarla como parámetro directamente. Los paquetes HTTP capturados se informan en la consola y se guardan en un archivo. La salida del archivo y la verbosidad de los informes pueden ser controladas mediante parámetros.

### Dependencias
- **Colorama**: Para estilizar la salida en la consola.
- **Psutil**: Proporciona utilidades para obtener información del sistema y procesos en ejecución.
- **Inquirer**: Utilizado para crear una interfaz de selección de interfaz de red.
- **Scapy**: Biblioteca de manipulación de paquetes de red.
- **Argparse**: Para analizar los argumentos de línea de comandos.

### Instalación

1. Clona este repositorio en tu máquina local:
    ```bash
    git clone [https://github.com/andresdrew02/PythonHTTPSniffer](https://github.com/andresdrew02/PythonHTTPSniffer)
    ```

2. Navega al directorio del proyecto:
    ```bash
    cd PythonHTTPSniffer
    ```

3. Instala las dependencias usando pip:
    ```bash
    pip3 install -r requirements.txt
    ```

### Uso
```bash
python3 sniffer.py [-h] [-i INTERFAZ] [-o SALIDA] [-v]
```

### Parámetros
- `-h, --help`: Muestra el mensaje de ayuda.
- `-i INTERFAZ, --interface INTERFAZ`: Especifica la interfaz de red a utilizar.
- `-o SALIDA, --output SALIDA`: Especifica el archivo de salida para guardar los paquetes capturados.
- `-v, --verbose`: Reporta todos los paquetes capturados en la consola.

### Ejemplo de Uso
```bash
python sniffer.py -i wlan0 -o salida.txt -v
```

Este comando ejecutará el script `sniffer.py` utilizando la interfaz de red `wlan0`, guardando los resultados en el archivo `salida.txt`, e informando todos los paquetes capturados en la consola.

### Notas
- Asegúrese de tener los permisos necesarios para ejecutar el script, especialmente para acceder a las interfaces de red.
- El script puede requerir privilegios de administrador según la plataforma y el entorno de ejecución.
- Este script está diseñado para propósitos educativos y de diagnóstico. Úselo de manera ética y legal, respetando la privacidad y la seguridad de las redes y sistemas.
