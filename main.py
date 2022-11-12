from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
# ir a setting , interprete y instalasr flask_jwt_extended
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from waitress import serve

import json
import datetime
import requests

app=Flask(__name__)
cors=CORS(app)
                            #mi contraseña
app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que se conveniente
jwt = JWTManager(app)

#para que sea la primera en ejecutarce
@app.before_request
def middleware():
    print("Entro al middleware!!")
    urlCliente = request.path
    metodoCliente=request.method

    if(urlCliente=="/login"):
        print("la url es /login, no valido")
        pass
    else:
        print("aqui se valida token")
        verify_jwt_in_request()
        #para validar los rol
        infoToken= get_jwt_identity()
        idRol=infoToken["rol"]["_id"]

        urlValidarPermiso=dataConfig['url-backend-security']+"permiso-rol/validar-permiso/rol/"+idRol
        headers = {"Content-Type": "application/json"}
        #pendiaente cambiar el url por ?
        bodyRequest = {
            "url":urlCliente,
            "metodo":metodoCliente
        }
        responseValidarPermiso=requests.get(urlValidarPermiso, json=bodyRequest, headers=headers)
        print("status code del servicio validar permiso", responseValidarPermiso)

        if(responseValidarPermiso.status_code==200):
            print("el cliente si tiene permisos")
            pass
        else:
            return {"mensake":"permiso denegado}"}, 401


@app.route("/login", methods=['POST'])
def validarUsuario():
    url= dataConfig['url-backend-registraduriasecurity']+"/usuariovalidar-usuario"

    headers={ "Content-Type":"application/json" }
    bodyRequest= request.get_json()
    response = requests.post(url, json=bodyRequest, headers=headers)

    if(response.status_code==200):
        print("el usuario se valido correctamente")
        infoUsuario= response.json()

        tiempoToken= datetime.timedelta(seconds=60*60)
        newToken = create_access_token(identity=infoUsuario, expire_delta=tiempoToken)

        return {"token":newToken}
    else:
        print("error en validacion usuario")
        return {"mensaje":"usuario y contraseña errados"}, 401


@app.route("/usuario", methods=['GET'])
def listarUsuarios():
    url = dataConfig['url-backend-registraduriasecurity'] + "/usuario"
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()
@app.route("/usuario/<string:idUsuario>", methods=['GET'])
def buscarUsuario(idUsuario):
    url = dataConfig['url-backend-registraduriasecurity'] + "/usuario"+idUsuario
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()

@app.route("/usuario", methods=['POST'])
def crearUsuario():
    url = dataConfig['url-backend-registraduriasecurity'] + "/usuario"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()
    response = requests.get(url, json=body, headers=headers)
    return response.json()

@app.route("/usuario/<string:idUsuario>", methods=['PUT'])
def actualizarUsuario(idUsuario):
    url = dataConfig['url-backend-registraduriasecurity'] + "/usuario"+idUsuario
    headers = {"Content-Type": "application/json"}
    body = request.get_json()
    response = requests.get(url, json=body, headers=headers)
    return response.json()

@app.route("/usuario/<string:idUsuario>/rol/<string:idRol>", methods=['PUT'])
def asignarRolAUsuario(idUsuario, idRol):
    url = dataConfig['url-backend-registraduriasecurity'] + "/usuario"+idUsuario+"/rol/"+idRol
    headers = {"Content-Type": "application/json"}
    body = request.get_json()
    response = requests.get(url, json=body, headers=headers)
    return response.json()
@app.route("/usuario/<string:idUsuario>", methods=['DELETE'])
def eliminarUsuario(idUsuario):
    url = dataConfig['url-backend-registraduriasecurity'] + "/usuario" + idUsuario
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()


#fin rutas usuario
##############################################
# permiso rol
@app.route("/permiso-rol/rol/{id_rol}/permiso/{id_permiso}", methods=['POST'])
def crearPermisoRol(id_rol,id_permiso):
    url = dataConfig['url-backend-registraduriasecurity'] + "/permiso-rol/rol/" + id_rol +"/permiso/" + id_permiso
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, headers=headers)
    return response.json()

@app.route("/permiso-rol", methods=['GET'])
def listarPermisoRol():
    url = dataConfig['url-backend-registraduriasecurity'] + "/permiso-rol"
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()
@app.route("/permiso-rol/<string:id>", methods=['GET'])
def consultarPermisoRol(id):
    url = dataConfig['url-backend-registraduriasecurity'] + "/permiso-rol" + id
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()

@app.route("/permiso-rol/<string:id>/rol/<string:idRol>/permiso/<string:idPermiso>", methods=['PUT'])
def modificacionPermisoRol(id,idRol,idPermiso):
    url = dataConfig['url-backend-registraduriasecurity'] + "/permiso-rol/"+id+"/rol/"+ idRol+"/permiso/"+idPermiso
    headers = {"Content-Type": "application/json"}
    response = requests.put(url, headers=headers)
    return response.json()

@app.route("/permiso-rol/<string:id>", methods=['DELETE'])
def eliminarPermisoRol(id):
    url = dataConfig['url-backend-registraduriasecurity'] + "/permiso-rol" + id
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()

#fin rutas permiso rol
#######################################################
#rutas candidato
@app.route("/candidato/<string:idCandidato>/partido/<string:idPartido>", methods=['PUT'])
def asignarPartidoCandidato(idCandidato, idPartido):
    url = dataConfig['url-backend-registraduria'] +"/candidato/"+idCandidato+"/partido/"+idPartido
    headers = {"Content-Type": "application/json"}
    response = requests.put(url, headers=headers)
    return response.json()

#ruta que recibe un valor para buscar candidato
@app.route("/candidato/<string:cedula>",methods=['GET'])
    #la funcion recibe la cedula del candidato
def consultaCandidato(cedula):
    url = dataConfig['url-backend-registraduria'] + "/candidato/" + cedula
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()


@app.route("/candidato",methods=['POST'])
def crearCandidato():
    url = dataConfig['url-backend-registraduria'] + "/candidato"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return response.json()

@app.route("/candidato/<string:cedula>",methods=['PUT'])
def actualizarCandidato(cedula):
    url = dataConfig['url-backend-registraduria'] + "/candidato/" + cedula
    headers = {"Content-Type": "application/json"}
    response = requests.put(url, headers=headers)
    return response.json()
@app.route("/candidato/<string:cedula>",methods=['DELETE'])
def eliminarCandidato(cedula):
    url = dataConfig['url-backend-registraduria'] + "/candidato/" + cedula
    headers = {"Content-Type": "application/json"}
    response = requests.delete(url, headers=headers)
    return response.json()

#fin rutas candidato
#=================================================================
#rutas partido
@app.route("/crear-partido", methods=['POST'])
def crearPartido():
    url = dataConfig['url-backend-registraduria'] + "/partido"
    headers = {"Content-Type": "application/json"}
    body= request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return response.json()

@app.route("/partido",methods=['GET'])
def listaPartido():
    url = dataConfig['url-backend-registraduria'] + "/partido"
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()

@app.route("/partido/<string:id>",methods=['GET'])
def consultaPartido(id):
    url = dataConfig['url-backend-registraduria'] + "/partido" + id
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()


@app.route("/partido/<string:id>",methods=['PUT'])
def actualizarPartido(id):
    url = dataConfig['url-backend-registraduria'] + "/partido"+ id
    headers = {"Content-Type": "application/json"}
    body = request.get_json()
    response = requests.put(url, json=body, headers=headers)
    return response.json()

@app.route("/partido/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
    url = dataConfig['url-backend-registraduria'] + "/partido"+ id
    headers = {"Content-Type": "application/json"}
    response = requests.delete(url, headers=headers)
    return response.json()
#Fin rutas Partido

def loadFileConfig():
    with open('config.json') as f:
         data = json.load(f)
    return data
if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])
