import * as registerlib from "./register-lib.js";

$(document).ready( function () {
    let nextConter = 0;
    let BackupCodeFlag = false;

    $("#SecondAuthRegister").hide();
    $('#TOTP').hide();
    $("#EmailCodeW,#SMSCodeW").hide();
    $("#backupCode").hide();
    $("#BackUpCodeAlert").hide();

    $("#RePassword").blur(function () {
        let $PswAlert = $("#PswAlert");
        if (!registerlib.RepasswordChecker("Password", "RePassword")) {
            if ($PswAlert.length === 0){
                $("#RePassword").after('<b id="PswAlert"> Password mismatch!</b>');
                $PswAlert.css("color","red");
            }else{
                $PswAlert.css("color","red");
            }
        }else {$PswAlert.remove();}
    })

    $('#next').click(async function () {
        if (nextConter === 0){
            if (registerlib.RepasswordChecker("Password", "RePassword")) {
                $.get("register",
                    {
                        "stepCode": "0",
                        "UserName": $('#Username').val(),
                        "UserPsw": await registerlib.SHA256Hex($('#Password').val())
                    },"json"
                ).done(function (data) {
                    console.log(data);
                    if (data.statue === 200) {
                        $("#SecondAuthRegister").show();
                        $('#UsrandPSw').hide();
                        nextConter = 1;
                    } else if (data.statue === "-1") {
                        alert(data.message);
                    }else {
                        alert("internal error");
                    }
                })
            }
        }
        if (nextConter === 1){
            $.post("register",
                {
                    "stepCode":"2",
                    "TOTP":$("#TOTPCode").val(),
                    "EmailOTP":$("#EmailCode").val(),
                    "SMSOTP":$("#SMSCode").val()
                },"json"
            ).done(function (data) {
                if (data.statue === "-1"){
                    let $errormessage = $("#errormessage");
                    if (data.message0 !== undefined){$errormessage.append("TOTP error:"+ data.message0+" ");};
                    if (data.message1 !== undefined){$errormessage.append("SMS error:"+ data.message1);};
                    if (data.message2 !== undefined){$errormessage.append("Email error:"+data.message2);};
                }else if(data.statue === 302){
                    window.location.replace(data.location);
                }
            })
        }

    })

    $('#TOTPRequest').click(function () {
        $.get("register",
            {
                "stepCode":"1",
                "typeCode":"0",
            },"json"
        ).done(function (data) {
            if (data.statue === 200) {
                registerlib.TOTPQRCodeGenerator("TOTP", data.TOTPTokenUrl);
                $('#TOTPToken').text("Hand input to Authenticator App if necessary: "+data.TOTPToken);
                $('#TOTP').show();
                if (BackupCodeFlag === false){
                    $.get("register",
                        {
                            "stepCode": "1",
                            "typeCode": "3"
                        }, "json"
                    ).done(function (data) {
                        if (data.statue === 200) {
                            $("#backupCode").show();
                            $("#BackUpCodeAlert").show();
                            for (let i = 0;i < data.BackUpCodeArray.length;i++){
                                $("#BackUpCodeAlert").append(" "+data.BackUpCodeArray[i]);
                            }
                            BackupCodeFlag = true;
                        }
                    })
                }

            }
        })
    })

    $("#SMSSender").click(function () {
        $.get("register",
            {
                "stepCode":"1",
                "typeCode":"1",
                "PhoneNumber": $("#PhoneNumber").val()
            },"json"
        ).done(function (data) {
            if (data.statue === 200){
                $("#SMSSender").text("SMS Sent");
                $("#SMSCodeW").show();
                if (BackupCodeFlag === false){
                    $.get("register",
                        {
                            "stepCode": "1",
                            "typeCode": "3"
                        }, "json"
                    ).done(function (data) {
                        if (data.statue === 200) {
                            $("#backupCode").show();
                            $("#BackUpCodeAlert").show();
                            for (let i = 0;i < data.BackUpCodeArray.length;i++){
                                $("#BackUpCodeAlert").append(" "+data.BackUpCodeArray[i]);
                            }
                            BackupCodeFlag = true;
                        }
                    })
                }
            }else {
                alert(data.message);
            }
        })
    })

    $("#EmailSender").click(function () {
        $.get("register",
            {
                "stepCode":"1",
                "typeCode":"2",
                "Email": $("#EmailAddress").val()
            },"json"
        ).done(function (data) {
            if (data.statue === 200){
                $("#EmailSender").text("Email Sent");
                $("#EmailCodeW").show();
                if (BackupCodeFlag === false){
                    $.get("register",
                        {
                            "stepCode": "1",
                            "typeCode": "3"
                        }, "json"
                    ).done(function (data) {
                        if (data.statue === 200) {
                            $("#backupCode").show();
                            $("#BackUpCodeAlert").show();
                            for (let i = 0;i < data.BackUpCodeArray.length;i++){
                                $("#BackUpCodeAlert").append(" "+data.BackUpCodeArray[i]);
                            }
                            BackupCodeFlag = true;
                        }
                    })
                }
            }else {
                alert(data.message);
            }
        })
    })
})