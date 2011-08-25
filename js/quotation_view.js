$(function() {
    $('#print').click(function() {
        $('#main').height('');
        window.print();
    });
    $.count_prices = function() {
        var sub_total_price = 0;
        var vat = 0.05;
        var vat_price = 0;
        var total_price = 0;
        
        $('.item_price').each(function(i, el) {
            $.item_quantity = $(el).parent().find('.item_quantity');
            $.item_sub_total = $(el).parent().find('.item_sub_total');
            var item_quantity = (isNaN(parseFloat($.item_quantity.html()))) ? 0 : parseFloat($.item_quantity.html());
            var item_price = (isNaN(parseFloat($(el).html()))) ? 0 : parseFloat($(el).html());
            var tmp_value = (item_quantity * item_price).toFixed(2);
            $.item_sub_total.html(tmp_value);
        });
    }

    // 啟動時先算第一次
    $.count_prices();
});
