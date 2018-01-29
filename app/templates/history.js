
{% macro hostoryjs() %}
    // set up history data table
    $("#tbl_history").DataTable({
        "paging" : true,
        "lengthChange" : false,
        "searching" : true,
        "ordering" : true,
        "info" : true,
        "autoWidth" : false
    });
    $(document.body).on('click', '.history-info-button', function() {
        
        var historyid = $(this).val();

        senddata = {'historyid': historyid}
        $.ajax({
            type : "POST",
            url : "{{ url_for('history_info') }}",
            data : senddata,
            //contentType : "application/json; charset=utf-8",
            crossDomain : true,
            dataType : "json",

            success : function(retdat) {
                console.log("In Success " + historyid + " " + retdat.status)
                console.log("In Success " + retdat.retval)
                var modal = $("#modal_history_info");
                var show = JSON.stringify(retdat.retval, null, '\t');
                $('#modal-code-content').html(show);
                modal.modal('show');
            }
        });

        console.log('history-info-button the historyid be "' + historyid + '"');
    });
{% endmacro %}
