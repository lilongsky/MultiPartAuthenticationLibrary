import "./jquery-3.6.3.js"

export async function LoginFirst(formid, userid, userpswid, md5pswid, urlOfFirstLogin) {

    let
        username = $('#' + userid),
        userpsw = $('#' + userpswid),
        sha256psw = $('#' + md5pswid),
        devOpt = $('input[name=devOption]:checked')

    async function SHA256Hex(message) {
        const msgUint8 = new TextEncoder().encode(message); // encode as (utf-8) Uint8Array
        const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8); // hash the message
        const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
        // convert bytes to hex string
        return hashArray
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    }

    sha256psw.val(await SHA256Hex(userpsw.val()));

    function PAPPost(url) {
        $.post(url,
            {
                "code": 1,
                "username": username.val(),
                "response": sha256psw.val(),
                "devOpt": devOpt.val()
            },"json")
            .done(function (data) {
                if (data.statues === 302) {
                    console.log(data);
                    window.location.replace(data.location);
                }
                else{
                    alert(data.message)
                }

            })
            .fail(function () {
                alert("PAP unknow error");
            })
    }
    function CHAPGetRandomValue(url, id) {

        $.get(url,
            {
                "id": id,
                "devOpt": devOpt.val()
            }, "json"
        ).done(function (data) {

            CHAPPost(urlOfFirstLogin,id,data);

        }).fail(function (data) {
            return data;
        })
    }

    async function CHAPPost(url, id, cValueJson) {

        if (cValueJson.id !== id) {
            alert("Id mismatch");
        }
        let randomValueWithID = cValueJson.randomValue;
        let cPsw = await SHA256Hex(sha256psw.val() + randomValueWithID)
        $.post(url,
            {
                "id": id,
                "username": username.val(),
                "response": cPsw,
                "devOpt": devOpt.val()
            },"json")
            .done(function (data) {
                if (data.statues === 302) {
                    console.log(data);
                    window.location.replace(data.location);
                }
                else{
                    alert(data.message);
                }

            })
            .fail(function () {
                alert("CHAP unknow error");
            })
    }

    if (devOpt.val() === "PAP") {
        alert("PAP");
        PAPPost(urlOfFirstLogin);
    } else if (devOpt.val() === "CHAP") {
        alert("CHAP");
        let array = new Uint32Array(1);
        window.crypto.getRandomValues(array);
        let challengeID = array[0].toString();
        CHAPGetRandomValue(urlOfFirstLogin, challengeID);
    }
}

export async function LoginSecond(AuthType,TOTPId,SMSOTPId,EmailOTPId,BackupId,urlOfSecondLogin){

    let
        TOTP =$('#'+TOTPId),
        SMSOTP = $('#'+SMSOTPId),
        EmailOTP = $('#'+EmailOTPId),
        BackUpCode = $('#'+BackupId);

    $.post(urlOfSecondLogin,
        {
            "TOTP":TOTP.val(),
            "SMSOTP":SMSOTP.val(),
            "EmailOTP":EmailOTP.val(),
            "BackUpCode":BackUpCode.val()
        },
        "json").done(
            function (data) {
                if (data.statues === 302) {
                    console.log(data);
                    window.location.replace(data.location);
                }
                else{
                    alert(data.message);
                }
            }
    )
}

