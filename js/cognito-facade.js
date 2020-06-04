var userPool
var cognitoUser

// import { CognitoUserPool, AuthenticationDetails, CognitoUser } from 'amazon-cognito-identity-js'


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

function cadastrarCognito(userName, name, userEmail, userPassword, fone, callback) {
    let dataEmail = {
        Name: 'email',
        Value: userEmail
    }

    let dataUserName = {
        Name: 'preferred_username',
        Value: userName
    }

    let dataPersonName = {
        Name: 'name',
        Value: name
    }

    let dataFone = {
        Name: 'phone_number',
        Value: fone
    }

    let attributeList = [
        new AmazonCognitoIdentity.CognitoUserAttribute(dataEmail),
        new AmazonCognitoIdentity.CognitoUserAttribute(dataPersonName),
        new AmazonCognitoIdentity.CognitoUserAttribute(dataUserName),
        new AmazonCognitoIdentity.CognitoUserAttribute(dataFone)
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


// export const sendMfaCode = MFACode => {
//     cognitoUser.sendMFACode(MFACode, cognitoCallbacks)
//   }

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
        mfaSetup: function(challengeName, challengeParameters) {
            cognitoUser.associateSoftwareToken(this);
        },
    
        associateSecretCode: function(secretCode) {
            onValueChanged(secretCode, userName.value);
            
            // window.open("file:///home/ricardo/Documentos/tecban/Auth-AWS-Cognito-SDK-JS/qrcode.html?account=" + userName.value + "&secret=" + secretCode, "_blank");

            var challengeAnswer = prompt('Please input the TOTP code.', '');
            cognitoUser.verifySoftwareToken(challengeAnswer, 'My TOTP device', this);
        },
    
        selectMFAType: function(challengeName, challengeParameters) {
            var mfaType = prompt('Please select the MFA method.', ''); // valid values for mfaType is "SMS_MFA", "SOFTWARE_TOKEN_MFA"
            cognitoUser.sendMFASelectionAnswer(mfaType, this);
        },
    
        totpRequired: function(secretCode) {
            var challengeAnswer = prompt('Please input the TOTP code.', '');
            cognitoUser.sendMFACode(challengeAnswer, this, 'SOFTWARE_TOKEN_MFA');
        },
    
        mfaRequired: function(codeDeliveryDetails) {
            var verificationCode = prompt('Please input verification code', '');
            cognitoUser.sendMFACode(verificationCode, this);
        },
        onFailure: err => {
            callback(err, null)
        },
        onSuccess: result => {
            callback(null, result)
            console.log(result)
        }
    }
}

function makeURI(secret, account) {
	var algorithm = "SHA256";
	var account = account;
	var issuer = "";
	var secret = secret;
	var digits = "6";
	var period = "30";
	var image = "";
	var type = "hotp";
	var uri = "otpauth://" + type + "/";

	if (issuer.length > 0)
		uri += encodeURIComponent(issuer) + ":";

	uri += encodeURIComponent(account);
	uri += "?secret=" + secret;
	uri += "&algorithm=" + algorithm;
	uri += "&digits=" + digits;
	uri += "&period=" + period;

	if (type == "hotp")
		uri += "&counter=0";

	if (image.length > 0)
		uri += "&image=" + encodeURIComponent(image);

	return uri;
}

function onValueChanged(secret, account) {
  
    // var prv = document.getElementById("preview");
    // var img = document.getElementById("image");
    // var src = img.value.length > 0 ? img.value : "img/freeotp.svg";
  
    // img.classList.remove("error");
    // prv.src = err ? "img/error.svg" : src;
  
    var uri = makeURI(secret, account);
    qrcode.clear();
    qrcode.makeCode(uri);
    document.getElementById("urilink").href = uri;
  }

  function onImageError() {
    document.getElementById("image").classList.add("error");
    document.getElementById("preview").src = "img/error.svg";
  }