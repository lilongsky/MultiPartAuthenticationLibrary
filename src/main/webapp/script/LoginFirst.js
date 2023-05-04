import * as loginlib from "./login-lib.js"

$(document).ready(function (){
    $('#register').click(function (){
        console.log("register click");
        window.location.replace("./register.html");
    });
    $('#submitButton').click(function (){

        loginlib.LoginFirst('login_form','username','password',
            'md5-password', "login-first").then(data =>{
            if (data.statues === 302) {
                window.location.replace(data.location);
            }
            else{
                alert(data.message);
            }
        }).catch(error=>{
            alert(error);
        });
    })
})