$(function() {
    $('input[type="button"]').click(function() {
        var d;
        if ($(this).val() == 'Encrypt') {
            d = GibberishAES.enc($('#data').val(), $('#pass').val(), 'pbkdf2');
        } else {
            d = GibberishAES.dec($('#data').val(), $('#pass').val(), 'pbkdf2');
        }
        $('#out').val(d);
    });
    var textBox = $('#out');
    textBox.on('focus', function() {
        textBox.select();
        textBox.onmouseup = function() {
            textBox.onmouseup = null;
            return false
        }
    });
});
