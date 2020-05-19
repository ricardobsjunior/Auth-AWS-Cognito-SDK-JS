var userPool
var cognitoUser

//obter dados de conexao com o cognito a partir do localstorage
function getPoolData() {
    return {
        UserPoolId: localStorage['aws-congnito-user-pool-id'],
        ClientId: localStorage['aws-congnito-app-id']
    }
}

function getUserPool() {
    if (userPool == undefined) {
        userPool = new AmazonCognitoIdentity.CognitoUserPool(getPoolData())
    }
    return userPool
}

function cadastrarCognito(userName, name, userEmail, userPassword, callback) {
    let dataEmail = {
        Name: 'email',
        Value: userEmail
    }

    let dataName = {
        Name: 'preferred_username',
        Value: userName
    }

    let dataPersonName = {
        Name: 'name',
        Value: name
    }

    let attributeList = [
        new AmazonCognitoIdentity.CognitoUserAttribute(dataEmail),
        new AmazonCognitoIdentity.CognitoUserAttribute(dataPersonName),
        new AmazonCognitoIdentity.CognitoUserAttribute(dataName)
    ]

    let userPool = getUserPool()
    userPool.signUp(userName, userPassword, attributeList, null, function (
        err,
        result
    ) {
        if (err) {
            callback(err, null)
        } else {
            cognitoUser = result.user
            callback(null, result)
        }
    })
}

function getUser(userName) {
    if (cognitoUser == undefined) {
        var userData = {
            Username: userName,
            Pool: getUserPool()
        }
        cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData)
    }

    return cognitoUser
}

function confirmaCadastroCognito(userName, code, callback) {
    getUser(userName).confirmRegistration(code, true, callback)
}

function efetuarLoginCognito(userName, password, callback) {
    let authenticationData = {
        Username: userName,
        Password: password
    }
    var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(
        authenticationData
    )

    getUser(userName).authenticateUser(
        authenticationDetails,
        tratarCallback(callback)
    )
}

function efetuarLogoutCognito(callback) {
    console.log('efetuando logout')

    if (userPool.getCurrentUser()){
        userPool.getCurrentUser().getSession((err, result) => {
            if(!err) {
                console.log(result)
            }
        })
    }

    userPool.getCurrentUser().signOut()
}

function apagarUsuarioCognito(callback) {
    console.log('apagando usuário')

    if (cognitoUser) {
        cognitoUser.deleteUser((err, result) => {
            if (err) {
                callback(err, null)
                return
            } else {
                cognitoUser = null
                callback(null, result)
            }
        })
        return
    }
    callback({ name: 'Erro', message: 'Usuario não está logado' }, null)
}


function trocarSenhaCognito(oldPassword, newPassword, callback) {
    console.log('trocando senha')
    if (cognitoUser) {
        cognitoUser.changePassword(oldPassword, newPassword, callback)
        return
    }

    callback({ name: "Erro: ", message: "Usuario não logado!" }, null)

}

function esqueciSenhaCognito(userName, callback) {
    console.log('esqueci senha')

    getUser(userName).forgotPassword(tratarCallback(callback))
}

function confirmarEsqueciSenha(userName, code, newPassword, callback) {
    console.log('confirmar esqueci senha')

    getUser(userName).confirmPassword(code, newPassword, tratarCallback(callback))
}

function consultarDadosUsuario(callback) {
    console.log('consultar dados usuário')

    if (cognitoUser) {
        cognitoUser.getUserAttributes((err, result) => {

            if (err) {
                callback({});
                return
            } else {
                let userInfo = { name: cognitoUser.username }
                for (let k = 0; k < result.length; k++) {
                    userInfo[result[k].getName()] = result[k].getValue();
                }
                userInfo["jwtToken"] = cognitoUser.signInUserSession.accessToken.getJwtToken();
                userInfo["idToken"] = cognitoUser.signInUserSession.idToken.getJwtToken();
                userInfo["refreshToken"] = cognitoUser.signInUserSession.refreshToken.getToken();
                
                var jwtToken = cognitoUser.signInUserSession.accessToken.getJwtToken();
                
                callback(userInfo);
            }

            
        })
    }
}

function tratarCallback(callback) {
    return {
        onFailure: err => {
            callback(err, null)
        },
        onSuccess: result => {
            callback(null, result)
            console.log(result)
        }
    }
}
