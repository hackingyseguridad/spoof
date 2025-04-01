## spoof ip tools test
# 
## http://www.hackingyseguridad.com/
#

Hay tres comportamientos probables a medida que el paquete se envía desde la LAN al enrutador:

El enrutador aplica el filtrado de ruta inversa y descarta el paquete.
El enrutador no filtra. En cambio, el enrutador lo trata como cualquier otro paquete de la LAN, lo que significa que la IP de origen se reemplaza con la IP del enrutador y el enrutador crea una entrada de seguimiento de conexión.
El enrutador no aplica filtrado o NAT. En cambio, el enrutador envía el paquete con una dirección de origen falsificada.
En el primer caso, no pasa nada más. En el tercer caso, el ISP puede descartar o reenviar el paquete. En uno de estos casos, el paquete falsificado llega hasta el objetivo. Pero no regresará ninguna respuesta a este enrutador, ya que iría a la IP falsificada.
