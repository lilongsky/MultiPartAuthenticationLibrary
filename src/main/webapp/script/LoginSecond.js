import * as loginlib from "./login-lib.js"

$(document).ready(function (){
    $("#submitButton").hide();
    let AuthType = -1;
    $.get("login-second",{"AuthType":"-1"},"json")
        .done(function (data) {
            console.log(data);
            if (data.statues === 200){
            }else if (data.statues === 302){
                window.location.replace("./index.html")
            } else{
                alert("internal error");
                window.location.replace("./index.html");
            }
            $("#submitButton").show();

            $("#SMSSender").click( function (){
                let $SMSSender = $(this);
                $SMSSender.prop("disabled", true);
                $.get("login-second",
                    {
                        "AuthTypeCode":"1"
                    },"json"
                ).done(function (data1) {
                    console.log(data1);
                    if (data1.statues === 200){
                        $SMSSender.text("SMS Sent");
                        $SMSSender.prop("disabled", false);
                    }else if (data1.statues === 403){
                        alert("too many times");
                    }
                });
            })

            $("#EmailSender").click( function () {
                let $EmailSender = $(this);
                $EmailSender.prop("disabled", true);
                $.get("login-second",
                    {
                        "AuthTypeCode":"2"
                    },"json"
                ).done(function (data2) {
                    console.log(data2);
                    if (data2.statues === 200){
                        $EmailSender.text("Email Sent");
                        $EmailSender.prop("disabled", false);
                    }else if (data2.statues === 403){
                        alert("too many times");
                    }
                });
            })

            $('#submitButton').click(function (){
                loginlib.LoginSecond(AuthType,"TOTP","SMS-OTP",
                    "EmailOTP","BackupCode","login-second").then(data => {
                    if (data.statues === 302) {
                        console.log(data);
                        window.location.replace(data.location);
                    }
                    else{
                        alert(data.message);
                    }
                    }
                )
            })
        }
    )

})