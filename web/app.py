from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from pymongo import MongoClient

import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://")
db = client.bankApi
users = db["Users"]


def UserExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData['username']
        password = postedData['password']

        if UserExist(username):
            retJson = {
                "status": "301",
                "msg": "Invalid Username"
            }
            return jsonify(retJson)
        hash_pass = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hash_pass,
            "Own": 0,
            "Debt": 0
        })

        retJson = {
            "status": 200,
            "msg": "You succesfully signed up for the Api"
        }
        return jsonify(retJson)

    def verifyPw(username, password):
        if not UserExist(username):
            return False

        hashed_pw = users.find({
            "Username": username
        })[0]["Password"]

        if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
            return True
        else:
            return False

    def cashWithUser(username):
        cash = users.find({
            "Username": username
        })[0]["Own"]
        return cash

    def debtWithUser(username):
        debt = users.find({
            "Username": username
        })[0]["Debt"]
        return debt

    def generateReturnDictionary(status, msg):
        retJson = {
            "status": status,
            "msg": msg
        }
        return retJson

    def verifyCredentials(username, password):
        if not UserExist(username):
            return generateReturnDictionary(301, "Invalit Username"), True

        correct_pw = verifyPw(username, password)

        if not correct_pw:
            return generateReturnDictionary(302, "Incorrect Password"), True

        return None, False

    def updateAccount(username, balance):
        users.update({
            "Username": username
        }, {
            "$set": {
                "Own": balance
            }
        })

    def updateDebt(username, balance):
        users.find({
            "Username": username
        }, {
            "$set": {
                "Debt": balance
            }
        })


class Add(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money = postedData["amount"]

        retJson, error = verifyCredentials(username,password)
        if error:
            return jsonify(retJson)
        if money <=0:
            return jsonify(generateReturnDictionary(304,"The money amount entered must be >0"))
        cash = cashWithUser(username)\
        money -= 1
        bank_cash = cashWithUser(username)
        updateAccount("BANK", bank_cash+1)
        updateAccount(username, cash+money)

        return jsonify(generateReturnDictionary(200,"Amount add successfully to Account"))


class Transfer(Resource):
    def post(self):
        postedData = request.get_json()
        