# spoof ip tools test
# 
# www.hackingyseguridad.com

Hay tres comportamientos probables a medida que el paquete se envía desde la LAN al enrutador:

El enrutador aplica el filtrado de ruta inversa y descarta el paquete.
El enrutador no filtra. En cambio, el enrutador lo trata como cualquier otro paquete de la LAN, lo que significa que la IP de origen se reemplaza con la IP del enrutador y el enrutador crea una entrada de seguimiento de conexión.
El enrutador no aplica filtrado o NAT. En cambio, el enrutador envía el paquete con una dirección de origen falsificada.
En el primer caso, no pasa nada más. En el tercer caso, el ISP puede descartar o reenviar el paquete. En uno de estos casos, el paquete falsificado llega hasta el objetivo. Pero no regresará ninguna respuesta a este enrutador, ya que iría a la IP falsificada.

El caso más interesante es aquel en el que se aplica NAT al paquete. El ISP ya no podrá abandonar el paquete en función de la IP de origen, porque en este caso la IP de origen es de hecho válida en lo que respecta al ISP. Pero esto no es muy dañino porque los paquetes se pueden filtrar fácilmente en función de la dirección IP de origen una vez que llegan al destino (suponiendo que la inundación es lo suficientemente grande como para ser notable en el destino). Tampoco se puede abusar fácilmente en un ataque de reflexión, porque las respuestas vuelven al enrutador NAT.

Lo que sucede con las respuestas que regresan al enrutador NAT es más interesante. Coincidirán con una entrada de seguimiento de conexión. Pero después de que se haya aplicado NAT, la dirección de destino no estará dentro de la LAN, sino externamente. En este punto hay algunos posibles resultados:

El enrutador puede negarse a reenviar el paquete porque se lo enviará de vuelta a la interfaz desde donde vino.
El enrutador puede reenviar el paquete a la red externa tan pronto como aplique NAT de acuerdo con la entrada de seguimiento de conexión.
El enrutador puede intentar realizar NAT en el paquete de nuevo, porque se iría en la interfaz externa.
El primer caso donde se descarta el paquete, no es particularmente interesante o perjudicial.

El segundo caso en el que el paquete se reenvía a la red externa es más interesante. Este es el caso en que el NAT impidió que se produjera una falsificación, pero un efecto secundario de esto es que al procesar la respuesta, en realidad produce un paquete con IP de fuente falsificada (efectivamente, la IP de origen y de destino del original) el paquete ha sido invertido).

Si el ISP no filtra el paquete debido a una IP de origen no válida, el tráfico de retorno será reenviado a la IP que fue falsificada en primer lugar. Y a la llegada se verá más o menos lo mismo que si no se hubiera producido NAT.

Pero dado que esto implica tres viajes a través de la conexión externa de la red atacante, la tasa de tráfico de ataque es limitada en comparación con lo que podría haber sido.

Si el enrutador intenta volver a NAT, las cosas se ponen un poco interesantes. El problema aquí es que no es el primer paquete de un flujo, por lo que la capa NAT puede no saber cómo manejarlo. Por lo tanto, el paquete puede descartarse debido a que se aplica NAT sin haber visto el primer paquete del flujo.

También es posible que se cree una entrada de seguimiento de conexión. Dado que la nueva entrada de seguimiento de conexión creada obviamente no se aplicó al primer paquete del flujo, no hay forma de que esto funcione en absoluto para una conexión TCP. Pero otros protocolos podrían funcionar incluso en tal escenario. Sin embargo, dado que este paquete en particular se debe a la suplantación de identidad, nada bueno vendrá de NATing it.

Si suponemos que se trata de un paquete TCP SYN-ACK, y el enrutador lo hace de nuevo a pesar de no tener ningún sentido, el ISP reenviará el SYN-ACK. El SYN-ACK desencadenará una respuesta RST (suponiendo que el destino es funcional), el RST volverá a través de ambas entradas de seguimiento de conexión y se reenviará al host desde donde vino el SYN-ACK y limpiará la conexión.

Como puede ver, hay muchos puntos en este flujo. Y es probable que haya algún resultado posible, que no he considerado.

Si su enrutador no tiene ningún filtro (el escenario más común) cambiará la dirección de origen en el paquete a su propia dirección y colocará una entrada en una tabla interna para "recordar" a qué conexión pertenece el paquete. Tan pronto como reciba una respuesta, el enrutador mirará esa tabla interna para ver dónde enviar el paquete. Como la dirección no proviene de ninguna red interna, el enrutador enviará el paquete a la puerta de enlace predeterminada.
