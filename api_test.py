from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from subprocess import Popen, PIPE
import json

app = Flask(__name__)
app.debug = True

app.config['JWT_SECRET_KEY'] = 't1NP63m4wnBg6nyHYKfmc2TpCOGI4nss'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 300
jwt = JWTManager(app)

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Falta el nombre de usuario"}), 400
    if not password:
        return jsonify({"msg": "Falta la contraseña"}), 400

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

@app.route('/add', methods=['POST'])
@jwt_required()
def add_rule():
    data = request.json

    source_ip = data['source_ip']
    source_ports = data['source_port'].split(',')
    destination_ip = data['destination_ip']
    destination_ports = data['destination_port'].split(',')

    if len(source_ports) == len(destination_ports):
        add_iptables_rules(source_ip, source_ports, destination_ip, destination_ports)
        return jsonify({'message': 'Reglas creadas correctamente!'}), 200
    else:
        return jsonify({'message': 'El número de puertos introducidos no es equivalente'}), 400 

def add_iptables_rules(source_ip, source_ports, destination_ip, destination_ports):
    if source_ip == 0:
        for i in range(len(source_ports)):            
            command = f"sudo iptables -t nat -A PREROUTING -p tcp --dport {source_ports[i]} -j DNAT --to-destination {destination_ip}:{destination_ports[i]}"
            process = Popen(command.split(), stdout=PIPE)
            output, _error = process.communicate()
    else:
        for i in range(len(source_ports)):            
            command = f"sudo iptables -t nat -A PREROUTING -s {source_ip} -p tcp --dport {source_ports[i]} -j DNAT --to-destination {destination_ip}:{destination_ports[i]}"
            process = Popen(command.split(), stdout=PIPE)
            output, _error = process.communicate()

@app.route('/delete', methods=['DELETE'])
@jwt_required()
def delete_rule():
    data = request.json
    destination_ip = data.get('destination_ip', None)

    if destination_ip is not None:
        delete_logic(destination_ip)
        return jsonify({'message': 'Conexion eliminada correctamente'}), 200
    else: 
        return jsonify({'message': 'IP inválida o campo vacío'}), 400  # Bad Request

def delete_logic(destination_ip):
    # Primero recuperamos una lista con todas las reglas
    command = "sudo iptables -t nat --line-numbers -L PREROUTING"
    process = Popen(command.split(), stdout=PIPE)
    output, _error = process.communicate()

    # Dividimos la salida en líneas, y pasamos por cada línea
    rules = output.decode().split('\n')
    rule_numbers = []
    for rule in rules:
        # Si la regla contiene la IP provista, almacenamos el número de regla
        if destination_ip in rule:
            rule_number = int(rule.split()[0])  # El número de regla está en la primer columna
            rule_numbers.append(rule_number)

    # Ordenamos los números de regla de mayor a menor
    rule_numbers.sort(reverse=True)

    # Eliminamos las reglas desde el mayor al menor
    for rule_number in rule_numbers:
        # El siguiente comando eliminará la regla
        command = f"sudo iptables -t nat -D PREROUTING {rule_number}"
        delete_process = Popen(command.split(), stdout=PIPE)
        delete_output, delete_error = delete_process.communicate()

@app.route('/modify', methods=['PUT'])
@jwt_required()
def modify_rule():
    data = request.json
    source_ip = data['source_ip']
    source_ports = data['source_port'].split(',')
    destination_ip = data['destination_ip']
    destination_ports = data['destination_port'].split(',')
  
    delete_logic(destination_ip)

    add_iptables_rules(source_ip, source_ports, destination_ip, destination_ports)

    return jsonify({'message': 'Regla actualizada correctamente!'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
