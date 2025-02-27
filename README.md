## PortScanner 🔍

Mapeamento do estado das portas de um host ou rede, fornecendo também a informação do sistema operacional do host. Abrange **IPv4, IPv6, TCP e UDP**.

---

## 📚 Informações e Links de Consulta

[Internet Protocol Flow Information Export (IPFIX)](https://www.ibm.com/docs/pt-br/qradar-on-cloud?topic=sources-ipfix) é uma tecnologia que monitora os fluxos de tráfego por meio de um **comutador** (dispositivo que serve para conectar vários dispositivos dentro de uma rede local — LAN) ou **roteador**. Esse fluxo possui sinalizadores referentes ao protocolo **TCP (Transmission Control Protocol)** que indicam o tipo do pacote, a exemplo de:

- Pacotes de tipo **SYN** (*flag* `0x02`)
- **RST** (*flag* `0x04`)
- **FIN** (*flag* `0x01`)
- **ACK** (*flag* `0x10`)

Essas *flags* são [descritas pela IBM como **tcpControlBits**](https://www.ibm.com/docs/pt-br/npi/1.3.0?topic=versions-ipfix-information-elements). Elas são relevantes para indicar o **estado de uma porta** durante seu escaneamento. De acordo com a [documentação do Nmap](https://nmap.org/man/pt_BR/man-port-scanning-techniques.html), uma porta pode estar em três diferentes estados:

- **Aberta**: Quando o pacote **SYN/ACK** é recebido, indicando que a porta está ouvindo.
- **Fechada**: Quando a resposta ao pacote **SYN** é um **RST** (reset), indicando que a porta não está ouvindo.
- **Filtrada**: Quando os [pacotes são descartados sem resposta](https://nmap.org/man/pt_BR/man-port-scanning-basics.html).

No contexto de uma **porta fechada**, a resposta ao pacote **SYN** é uma combinação de `RST` com `ACK`. Essas combinações são representadas pela soma das *flags*, resultando em `0x14` (**ACK `0x10` combinado com RST `0x04`**).

🔹 Ao contrário do **TCP**, o protocolo **UDP** não possui um handshake **SYN** para estabelecer uma conexão. Nesse protocolo, há dois estados diferentes:

1. **Aberta | Filtrada**: [Quando a porta não devolve resposta a solicitações.](https://nmap.org/man/pt_BR/man-port-scanning-basics.html)
2. **Fechada**: Quando a porta responde indicando indisponibilidade.

🔹 [Para identificar o **sistema operacional**, verifica-se o **TTL** (*Time to Live*) do pacote](https://ostechnix.com/identify-operating-system-ttl-ping/), já que essa informação é padronizada para diferentes sistemas no protocolo **IPv4**. A tabela abaixo apresenta essa padronização:

| **Time to Live (TTL)** | **Sistema Operacional** |
|------------------|----------------------|
| 32               | Windows 95/98/ME      |
| 64               | Linux, FreeBSD, macOS |
| 128              | Windows XP, 7, 8, 2003, 2008 |
| 255              | Solaris               |

ℹ️ A identificação do sistema operacional **não é direta** em endereços **IPv6**.

---

## 🌍 Escaneamento de Rede

No caso do escaneamento de uma **rede**, um processo similar ao **ping** é feito para [verificar se um **host está ativo**](https://nmap.org/man/pt_BR/man-host-discovery.html). Se ao enviar um pacote **ICMP** (*Internet Control Message Protocol*) do tipo **8 - Echo Request**, o host responder com um pacote **ICMP do tipo 0 - Echo Reply**, significa que o **host está ativo** e, portanto, suas portas podem ser escaneadas.

A relação entre os **números e nomes dos pacotes ICMP** é publicada pela organização [Internet Assigned Numbers Authority (IANA)](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml).

