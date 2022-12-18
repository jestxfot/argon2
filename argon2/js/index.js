function selectText(node) {
    var range, selection;
    if (document.body.createTextRange) {
        range = document.body.createTextRange();
        range.moveToElementText(node);
        range.select();
    } else if (window.getSelection) {
        selection = window.getSelection();
        range = document.createRange();
        range.selectNodeContents(node);
        selection.removeAllRanges();
        selection.addRange(range);
    } else {
        console.warn("Could not select text in node: Unsupported browser.");
    }
}

function displayFormErrors($form, errors) {
    var error, $invalidField;
    for (var fieldName in errors) {
        if (false === errors.hasOwnProperty(fieldName)) {
            continue;
        }
        error = errors[fieldName];
        $invalidField = $form.find("#" + fieldName);
        $invalidField.addClass('is-invalid');
        $invalidField.next('.invalid-feedback')
            .text(error);
    }
}

function validateData() {
    $(".form-control")
        .removeClass('is-invalid');
    $('.invalid-feedback')
        .text('');
    var plainTextMaxLength = 100000,
        saltMaxLength = 100,
        saltMinLength = 8,
        iterationsMinCount = 1,
        iterationsMaxCount = 20,
        hashMinLength = 4,
        hashMaxLength = 100,
        parallelismFactorMin = 1,
        parallelismFactorMax = 10,
        memoryMax = 128 * 1024;
    var errors = {};
    var $plainTextInput = $("#plain_text");
    var $saltInput = $("#salt");
    var $memoryInput = $("#memory");
    var $iterationsInput = $("#iterations");
    var $parallelismFactor = $("#parallelism");
    var $hashLengthInput = $("#hash_length");
    var plainText = $plainTextInput.val();
    if (plainText.length > plainTextMaxLength) {
        errors['plain_text'] = 'Plain text length must be maximum ' + plainTextMaxLength + ' characters long'
    }
    var salt = $saltInput.val();
    if (salt.length < saltMinLength) {
        errors['salt'] = 'Salt must be at least ' + saltMinLength + ' characters long';
    } else if (salt.length > saltMaxLength) {
        errors['salt'] = 'Salt must be maximum ' + saltMaxLength + ' characters long';
    }
    var iterationsCount = $iterationsInput.val();
    if (iterationsCount.length > 0) {
        if (parseInt(iterationsCount) < iterationsMinCount) {
            errors['iterations'] = 'Iterations count must be at least ' + iterationsMinCount;
        } else if (parseInt(iterationsCount) > iterationsMaxCount) {
            errors['iterations'] = 'Iterations count must be maximum ' + iterationsMaxCount;
        }
    }
    var hashLength = $hashLengthInput.val();
    if (hashLength.length > 0 && parseInt(hashLength) < hashMinLength) {
        errors['hash_length'] = 'Hash length must be at least ' + hashMinLength;
    } else if (parseInt(hashLength) > hashMaxLength) {
        errors['hash_length'] = 'Hash length can be maximum ' + hashMaxLength;
    }
    var parallelism = $parallelismFactor.val();
    if (parallelism.length > 0 && parseInt(parallelism) < parallelismFactorMin) {
        errors['parallelism'] = 'Parallelism factor must be at least ' + parallelismFactorMin;
    } else if (parseInt(parallelism) > parallelismFactorMax) {
        errors['parallelism'] = 'Parallelism factor can be maximum ' + parallelismFactorMax;
    }
    var memory = $memoryInput.val();
    if (memory.length > 0) {
        memory = parseInt(memory);
        var parallelismFactor = parseInt(parallelism) === 0 ? 1 : parseInt(parallelism);
        var memoryCostMin = 8 * parallelismFactor;
        if (memory < 0) {
            errors['memory'] = 'Memory cost must be at least 8 kilobyte';
        } else if (errors['parallelism'] === undefined) {
            if (memory < memoryCostMin) {
                errors['memory'] = 'Memory cost must be at least ' + Math.abs(memoryCostMin) + ' kilobyte';
            } else if (memory > memoryMax) {
                errors['memory'] = 'Memory cost can be maximum ' + memoryMax + ' kilobyte';
            }
        }
    }
    if (false === $.isEmptyObject(errors)) {
        displayFormErrors($("#generate_form"), errors);
        return false;
    }
    return true;
}

function generateSalt(length) {
    var salt = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < length; i++) {
        salt += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return salt;
}

function setupLoadingState($btn, $outputBlock) {
    $btn.addClass('disabled');
    $btn.find('.btn__text')
        .first()
        .html($btn.attr('data-loading-text'));
    $outputBlock.addClass('d-none');
}

function removeLoadingState($btn, $outputBlock) {
    $btn.removeClass('disabled');
    $btn.find('.btn__text')
        .first()
        .html($btn.attr('data-original-text'));
    $outputBlock.removeClass('d-none');
}
var calculateBtnCallBack = function(event) {
    event.preventDefault();
    if (false === validateData()) {
        return false;
    }
    const $calculateBtn = $(this);
    const $outputBlock = $("#output_block");
    setupLoadingState($calculateBtn, $outputBlock);
    $("#output_hash, #output_hex")
        .text(' -- ');
    var plainText = $("#plain_text")
        .val();
    var salt = $("#salt")
        .val();
    var iterationsCount = $("#iterations")
        .val();
    var memoryUsage = $("#memory")
        .val();
    var hashLength = $("#hash_length")
        .val();
    var parallelism = $("#parallelism")
        .val();
    var algorithmVariant;
    switch ($("input[name='radio']:checked")
        .val()) {
        case "1":
            algorithmVariant = argon2.ArgonType.Argon2i;
            break;
        case "2":
            algorithmVariant = argon2.ArgonType.Argon2d;
            break;
        case "3":
            algorithmVariant = argon2.ArgonType.Argon2id;
            break;
    }
    var hashingParamsConfig = {
        pass: plainText,
        salt: salt,
        time: iterationsCount.length === 0 ? 2 : parseInt(iterationsCount),
        mem: memoryUsage.length === 0 ? 16 : parseInt(memoryUsage),
        hashLen: hashLength.length === 0 ? 16 : parseInt(hashLength),
        parallelism: parallelism.length === 0 ? 1 : parseInt(parallelism),
        type: algorithmVariant,
        distPath: 'lib/argon2'
    };
    setTimeout(function() {
        argon2.hash(hashingParamsConfig)
            .then(function(res) {
                $("#output_hex")
                    .text(res.hashHex);
                $("#output_hash")
                    .text(res.encoded);
                removeLoadingState($calculateBtn, $outputBlock);
                gtag('event', 'Argon2 generated');
            })
            .catch(function() {
                removeLoadingState($calculateBtn, $outputBlock);
            });
    }, 500);
};
var copyCallback = function(elementId) {
    var $elem = document.getElementById(elementId);
    selectText($elem);
    $elem.setAttribute("title", "Copied");
    $($elem)
        .tooltip('show');
    setTimeout(function() {
        $($elem)
            .tooltip('dispose');
    }, 600);
};
const verifyHashBtnCallBack = function(event) {
    event.preventDefault();
    const $verifyBtn = $(this);
    const $outputBlock = $("#validation_result_block");
    setupLoadingState($verifyBtn, $outputBlock);
    $("#verified, #not_verified")
        .addClass('d-none');
    const hash = $("#verify_hash")
        .val();
    const plaintText = $("#verify_plain_text")
        .val();
    setTimeout(function() {
        argon2.verify({
                'pass': plaintText,
                'encoded': hash
            })
            .then(function() {
                removeLoadingState($verifyBtn, $outputBlock);
                $("#verified")
                    .removeClass('d-none');
                gtag('event', 'Argon2 hash verified');
            })
            .catch(function(err) {
                switch (err.code) {
                    case -32:
                        $("#not_verified")
                            .text("The supplied hash is invalid!");
                        break;
                    default:
                        $("#not_verified")
                            .text("The plain text does not match the supplied hash.");
                        break;
                }
                removeLoadingState($verifyBtn, $outputBlock);
                $("#not_verified")
                    .removeClass('d-none');
            });
    }, 500);
};
window.onload = function() {
    if (document.getElementById('st_gdpr_iframe')) {
        document.getElementById('st_gdpr_iframe')
            .setAttribute('title', 'ShareThis utility frame');
        var socialButtonImages = document.querySelectorAll('.st-btn img');
        for (var i = 0; i < socialButtonImages.length; i++) {
            var socialButtonImage = socialButtonImages[i];
            socialButtonImage.setAttribute('alt', socialButtonImage.parentElement.getAttribute('data-network') + ' icon');
        }
    }
    var $calculateBtn = document.getElementById("calculate_btn");
    $calculateBtn.addEventListener('click', calculateBtnCallBack);
    document.getElementById("clear_btn")
        .addEventListener('click', function(event) {
            event.preventDefault();
            $("#plain_text")
                .val('');
            $("#salt")
                .val('');
            $("#memory")
                .val(65536);
            $("#parallelism")
                .val(4);
            $("#iterations")
                .val(3);
            $("#hash_length")
                .val(16);
            $("#output_block")
                .addClass('d-none');
        }); {
        var clipboard1 = new ClipboardJS('#output_hash', {
            text: function(trigger) {
                return trigger.innerText;
            }
        });
        clipboard1.on('success', function() {
            copyCallback('output_hash');
        });
        var clipboard2 = new ClipboardJS('#copy_hash_btn');
        clipboard2.on('success', function() {
            copyCallback('output_hash');
        });
    } {
        const clipboard3 = new ClipboardJS('#output_hex', {
            text: function(trigger) {
                return trigger.innerText;
            }
        });
        clipboard3.on('success', function() {
            copyCallback('output_hex');
        });
        const clipboard4 = new ClipboardJS('#copy_hex_btn');
        clipboard4.on('success', function() {
            copyCallback('output_hex');
        });
    }
    document.getElementById("generate_salt")
        .addEventListener('click', function(ev) {
            document.getElementById('salt')
                .value = generateSalt(16);
        });
    const $verifyBtn = document.getElementById('verify_btn');
    $verifyBtn.addEventListener('click', verifyHashBtnCallBack);
};
