import * as loginlib from "./login-lib.js"


$(document).ready(function (){
    $('#submitButton').click(function (){
        loginlib.LoginFirst('login_form','username','password',
            'md5-password', "login-first");
    })
})