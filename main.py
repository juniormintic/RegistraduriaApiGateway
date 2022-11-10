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
import re

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

    if(urlCliente=="/ligin"):
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


@app.route("/login",methods=['POST'])
def validarUsuario():
    url= dataConfig['url-backend-security']+"/usuario/validar-usuario"

    headers={ "Content-Type":"application/json" }
    bodyRequest= request.get_json()
    response = requests.post(url, json=bodyRequest, headers=headers)

    if(response.status_code==200):
        print("el usuario se valido correctamente")
        infoUsuario= response.json()

        tiempoToken= datetime.timedelta(seconds=60)
        newToken = create_access_token(identity=infoUsuario, expire_delta=tiempoToken)

        return {"token":newToken}
    else:
        print("error en validacion usuario")
        return {"mensaje":"usuario y contraseña errados"}, 401

@app.route("/crear-estudiante", methods=['POST'])
def crearEstudiante():
    url = dataConfig['url-backend-academic'] + "/estudiante"
    headers = {"Content-Type": "application/json"}
    body= request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return  response.json()

def loadFileConfig():
    with open('config.json') as f:
         data = json.load(f)
    return data
if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])
