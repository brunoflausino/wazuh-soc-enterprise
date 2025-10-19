# **nwipe and Wazuh SIEM Integration**

## **1. Overview**

This guide provides a complete, step-by-step methodology for installing **nwipe** (a secure disk erasure tool) and integrating its execution logs with a **Wazuh 4.12** SIEM platform on **Ubuntu 24.04**.

[cite\_start]The primary objective is to create a complete audit trail for all disk erasure operations[cite: 201, 208]. [cite\_start]This is achieved by configuring Wazuh to ingest custom JSON logs generated during `nwipe` execution[cite: 203, 212, 279, 291].

This methodology follows a **safety-first principle**. [cite\_start]As etapas de instalação, configuração e teste são separadas para prevenir qualquer destruição acidental de dados durante a configuração[cite: 203, 226, 854].

## **2. System Environment**

  * [cite\_start]**Operating System:** Ubuntu 24.04 (x86\_64) [cite: 216, 848]
  * [cite\_start]**SIEM:** Wazuh 4.12 (Manager, Indexer, and Dashboard) [cite: 217, 849]
  * [cite\_start]**Privileges:** All commands require `sudo`[cite: 219, 850].

-----

## **3. Part 1: Safe Installation of nwipe**

Esta fase instala a ferramenta `nwipe`. [cite\_start]Nenhum disco será acedido ou apagado[cite: 229, 240, 857].

### **3.1. Tentativa 1: Instalação via APT (Recomendado)**

Primeiro, tente instalar o `nwipe` usando o gestor de pacotes do Ubuntu.

```bash
# 1. Atualizar os índices do APT
sudo apt-get update -y

# 2. Tentar instalar o pacote nwipe
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nwipe
```

### **3.2. Verificar a Instalação**

Execute o seguinte comando para verificar se a instalação foi bem-sucedida:

```bash
nwipe --version
```

  * Se este comando mostrar a versão do `nwipe`, a **Parte 1 está concluída**. Avance para a **Parte 2**.
  * Se o comando falhar (ou se a instalação via APT falhou), continue para a **Parte 3.3**.

### **3.3. Tentativa 2: Compilação a partir do Código Fonte**

Se o `nwipe` não estiver disponível nos repositórios, compile-o manualmente.

1.  **Instalar Dependências de Compilação:**
    [cite\_start]Instale as ferramentas necessárias para compilar o `nwipe`[cite: 223, 263, 851, 915, 916].

    ```bash
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential git autoconf automake libtool pkg-config \
        libparted-dev libncurses-dev
    ```

2.  **Clonar o Repositório:**
    [cite\_start]Clone o código fonte oficial do `nwipe`[cite: 266, 925].

    ```bash
    git clone --depth=1 https://github.com/martijnvanbrummelen/nwipe.git /tmp/nwipe_source
    ```

3.  **Compilar e Instalar:**
    [cite\_start]Entre no diretório, configure, compile e instale o binário [cite: 266, 267, 926-930].

    ```bash
    cd /tmp/nwipe_source

    # Gerar scripts de configuração, se necessário
    if [ -x ./autogen.sh ]; then
      ./autogen.sh
    fi

    # Configurar para instalar em /usr
    ./configure --prefix=/usr

    # Compilar usando todos os cores do processador
    make -j"$(nproc)"

    # Instalar o binário no sistema
    sudo make install
    ```

4.  **Verificar a Instalação (Novamente):**
    [cite\_start]Confirme que o `nwipe` está agora instalado[cite: 268, 269, 933, 935].

    ```bash
    nwipe --version
    ```

5.  **Limpeza:**
    Remova o diretório do código fonte.

    ```bash
    cd ~
    rm -rf /tmp/nwipe_source
    ```

-----

## **4. Part 2: Configuração da Integração com Wazuh**

[cite\_start]Esta fase configura o Wazuh (agente ou gestor) para monitorizar um ficheiro de log JSON dedicado para o `nwipe`[cite: 279, 291].

### **4.1. Definir Permissões e Variáveis**

1.  Primeiro, identifique o grupo de utilizador correto da sua instalação Wazuh (normalmente é `wazuh`):

    ```bash
    # Este comando guarda o nome do grupo na variável $OSSEC_GRP
    OSSEC_GRP=$(stat -c %G /var/ossec)

    # Verifique se funcionou (deve imprimir 'wazuh' ou similar)
    echo "Grupo Wazuh detectado: $OSSEC_GRP"
    ```

2.  [cite\_start]Crie o diretório de log para o `nwipe` e atribua a propriedade ao grupo Wazuh[cite: 1033]:

    ```bash
    sudo install -d -m 0750 -o root -g $OSSEC_GRP /var/log/nwipe
    ```

3.  [cite\_start]Crie o ficheiro de log JSON vazio e atribua as permissões corretas[cite: 1035]:

    ```bash
    sudo install -m 0640 -o root -g $OSSEC_GRP /dev/null /var/log/nwipe/wazuh_events.log
    ```

### **4.2. Configurar Logrotate**

Crie um ficheiro de rotação de logs para evitar que este ficheiro cresça indefinidamente.

1.  Abra um novo ficheiro de configuração do logrotate:

    ```bash
    sudo nano /etc/logrotate.d/nwipe
    ```

2.  Cole o seguinte conteúdo. [cite\_start]Certifique-se de **substituir `$OSSEC_GRP`** pelo nome do seu grupo (ex: `wazuh`) [cite: 1042-1052].

    ```ini
    /var/log/nwipe/*.log {
        daily
        rotate 14
        missingok
        compress
        delaycompress
        notifempty
        create 0640 root wazuh
    }
    ```

    *(Substitua `wazuh` se o seu `$OSSEC_GRP` for diferente.)*

### **4.3. Configurar o Wazuh (ossec.conf)**

1.  [cite\_start]Faça um backup do seu ficheiro `ossec.conf`[cite: 1064]:

    ```bash
    sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak_$(date +'%Y%m%d_%H%M%S')
    ```

2.  Edite o ficheiro `ossec.conf` para adicionar o novo ficheiro de log:

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

3.  [cite\_start]Adicione o seguinte bloco `<localfile>` dentro da secção `<ossec_config>`, de preferência junto de outros blocos `<localfile>` [cite: 1075-1079]. [cite\_start]Este bloco instrui o Wazuh a ler o ficheiro como JSON[cite: 213, 844, 954, 1232, 1247].

    ```xml
      <localfile>
        <location>/var/log/nwipe/wazuh_events.log</location>
        <log_format>json</log_format>
      </localfile>
    ```

4.  **(Obrigatório para Depuração)** Assegure-se de que o arquivamento de todos os logs (mesmo os que não disparam regras) está ativo. [cite\_start]Dentro do bloco `<global>`, verifique se `<logall_json>yes</logall_json>` está presente[cite: 214, 351, 846, 1200, 1235, 1248].

    ```xml
      <global>
        <logall_json>yes</logall_json>
        ...
      </global>
    ```

### **4.4. Adicionar Regras Personalizadas (local\_rules.xml)**

1.  Edite o seu ficheiro de regras locais:

    ```bash
    sudo nano /var/ossec/etc/rules/local_rules.xml
    ```

2.  Adicione o seguinte grupo de regras. [cite\_start]Se o ficheiro estiver vazio, certifique-se de que o cola entre as tags `<group name="local,">` e `</group>` [cite: 1103-1127].

    ```xml
    <group name="nwipe,">
      <rule id="100500" level="3">
        <decoded_as>json</decoded_as>
        <field name="component">^nwipe-wrapper$</field>
        <field name="msg">^INICIO$</field>
        <description>NWipe: start execution</description>
        <options>no_full_log</options>
      </rule>

      <rule id="100501" level="3">
        <decoded_as>json</decoded_as>
        <field name="component">^nwipe-wrapper$</field>
        <field name="msg">^FIM$</field>
        <field name="level">^info$</field>
        <description>NWipe: successful completion</description>
        <options>no_full_log</options>
      </rule>

      <rule id="100502" level="10">
        <decoded_as>json</decoded_as>
        <field name="component">^nwipe-wrapper$</field>
        <field name="msg">^FIM$</field>
        <field name="level">^error$</field>
        <description>NWipe: completion with error</description>
      </rule>
    </group>
    ```

    [cite\_start]*Nota: Estas regras usam `<decoded_as>json</decoded_as>`, que é a sintaxe correta para regras de JSON[cite: 338, 374].*

### **4.5. Aplicar Alterações**

Reinicie o serviço Wazuh para carregar as novas configurações e regras.

```bash
# Se estiver no Wazuh Manager
sudo systemctl restart wazuh-manager

# Se estiver num Wazuh Agent
sudo systemctl restart wazuh-agent
```

-----

## **5. Part 3: Geração de Eventos de Teste**

Esta fase valida a pipeline de logs **sem executar o nwipe**. [cite\_start]Vamos escrever manualmente eventos JSON simulados no ficheiro de log monitorizado[cite: 305, 1162].

Execute os seguintes comandos no terminal. [cite\_start]Eles irão simular um início, um sucesso e um erro [cite: 1188-1197].

```bash
# 1. Simular evento de INÍCIO (Nível 3)
echo '{"ts":"$(date -u +'%Y-%m-%dT%H:%M:%SZ')","component":"nwipe-wrapper","level":"info","msg":"INICIO","extra":{"device":"/dev/TEST","args":"--method dodshort --verify last","runlog":"/var/log/nwipe/nwipe_TEST.log"}}' | sudo tee -a /var/log/nwipe/wazuh_events.log

# 2. Simular evento de FIM com SUCESSO (Nível 3)
echo '{"ts":"$(date -u +'%Y-%m-%dT%H:%M:%SZ')","component":"nwipe-wrapper","level":"info","msg":"FIM","extra":{"device":"/dev/TEST","rc":0}}' | sudo tee -a /var/log/nwipe/wazuh_events.log

# 3. Simular evento de FIM com ERRO (Nível 10)
echo '{"ts":"$(date -u +'%Y-%m-%dT%H:%M:%SZ')","component":"nwipe-wrapper","level":"error","msg":"FIM","extra":{"device":"/dev/TEST_FAIL","rc":1,"error":"simulado"}}' | sudo tee -a /var/log/nwipe/wazuh_events.log
```

-----

## **6. Part 4: Validação e Verificação**

Vamos verificar se os eventos de teste geraram os alertas corretos no Wazuh Manager.

### **6.1. Verificação (archives.json)**

[cite\_start]Graças à configuração `<logall_json>yes</logall_json>`, podemos ver os logs brutos a chegar ao manager[cite: 351, 1201, 1237].

```bash
# Monitorize os logs de arquivo em tempo real
sudo tail -f /var/ossec/logs/archives/archives.json | grep "nwipe-wrapper"
```

  * [cite\_start]**Resultado Esperado:** Você deverá ver os três eventos JSON que simulou a aparecerem neste ficheiro [cite: 359-366]. Se aparecerem, o Wazuh está a ler o ficheiro de log corretamente.

### **6.2. Verificação (alerts.json)**

Agora, verifique se as suas regras personalizadas (100500, 100501, 100502) dispararam.

```bash
# Monitorize os logs de alerta em tempo real
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep "NWipe:"
```

  * [cite\_start]**Resultado Esperado:** Você deverá ver três alertas JSON, um para cada regra, confirmando que os níveis e descrições corretos foram acionados[cite: 368, 369, 370].

### **6.3. Verificação (wazuh-logtest)**

[cite\_start]Para uma depuração detalhada, use a ferramenta `wazuh-logtest`[cite: 338, 1214].

1.  Execute a ferramenta:

    ```bash
    sudo /var/ossec/bin/wazuh-logtest
    ```

2.  Cole uma das suas linhas de log JSON e prima Enter:
    `{"ts":"2025-10-18T06:16:02Z","component":"nwipe-wrapper","level":"error","msg":"FIM","extra":{"device":"/dev/TEST_FAIL","rc":1,"error":"simulado"}}`

3.  **Resultado Esperado:** A ferramenta deve mostrar-lhe que o `decoder: 'json'` foi usado e que a `rule id: '100502'` (nível 10) foi disparada.

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab – Threat Intelligence Stack*
