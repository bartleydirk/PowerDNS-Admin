
{% macro domainjs(editable_records, domain, default_record_table_size_setting, record_helper_setting, rrsetid) %}
// superglobals
window.records_allow_edit = {{ editable_records|tojson }};
window.nEditing = null;
window.nNew = false;

// set up user data table
var table = $("#tbl_records").DataTable({
    "paging" : true,
    "lengthChange" : true,
    "searching" : true,
    "ordering" : true,
    "info" : true,
    "autoWidth" : false,
    {% if default_record_table_size_setting in ['5','15','20'] %}
    "lengthMenu": [ [5, 15, 20, -1],
                    [25, 50, 75, 100, "All"]],
    {% else %}
    "lengthMenu": [ [5, 15, 20, {{ default_record_table_size_setting }}, -1],
                    [5, 15, 20, {{ default_record_table_size_setting }}, "All"]],
    {% endif %}
    "pageLength": {{ default_record_table_size_setting }},
    "language": {
        "lengthMenu": " _MENU_ records"
    },
    "retrieve" : true,
    "columnDefs": [
        {
            type: 'natural',
            targets: [0, 4]
        },
        {
            // hidden column so that we can add new records on top
            // regardless of whatever sorting is done
            visible: false,
            targets: [ 7 ]
        },
        {
            // History Link Column
            visible: true,
            targets: [ 8 ]
        }
    ],
    "orderFixed": [[7, 'asc']]
});
//$( document ).ready( onload() );

    console.log('onload');

    // handle apply changes button
    //$('#button_apply_changes').click(function(e) {
    $(document.body).on("click", "#button_apply_changes", function(e) {
        console.log('#button_apply_changes');
        var modal = $("#modal_apply_changes");
        var table = $("#tbl_records").DataTable();
        var domain = $(this).prop('id');
        var info = "Are you sure you want to apply your changes?"; 
        modal.find('.modal-body p').text(info);
        modal.find('#button_apply_confirm').click(function() {
            var data = getTableData(table);
            console.log('button_apply_changes data is "' + data.length + '"')
            applyChanges(data, "{{ url_for('record_apply', domain_name=domain.name) }}", true, false, {{ rrsetid }});
            modal.modal('hide');
        })
        modal.modal('show');
        //onbuttonchange();
    });

    // handle add record button
    //$('#button_add_record').click(function(e) {
    $(document.body).on("click", "#button_add_record", function(e) {
        console.log('#button_add_record');
        if (nNew || nEditing) {
            var modal = $("#modal_error");
            modal.find('.modal-body p').text("Previous record not saved. Please save it before adding more record.");
            modal.modal('show');
            return;
        }
        // clear search first
        $("#tbl_records").DataTable().search('').columns().search('').draw();

        // add new row
        var default_type = records_allow_edit[0]
        var nRow = jQuery('#tbl_records').dataTable().fnAddData(['', default_type, 'Active', 3600, '', '', '', '0', '']);
        editRow($("#tbl_records").DataTable(), nRow);
        document.getElementById("edit-row-focus").focus();
        nEditing = nRow;
        nNew = true;
        //onbuttonchange();
    });

    //handle update_from_master button  I do not think this button exists any more
    //$('#button_update_from_master').click(function(e) {
    $(document.body).on("click", "#button_update_from_master", function(e) {
        console.log('.button_update_from_master');
        var domain = $(this).prop('id');
        applyChanges({'domain': domain}, $SCRIPT_ROOT + '/domain/' + domain + '/update', true, false, {{ rrsetid }});
    });
    //onbuttonchange();

//function onbuttonchange() {
    console.log('onbuttonchange');
    // handle delete button
    //$('.button_delete').unbind().click(function(e) {
    $(document.body).on("click", ".button_delete", function(e) {
        console.log('.button_delete');
        e.stopPropagation();
        var modal = $("#modal_delete");
        var table = $("#tbl_records").DataTable();
        var record = $(this).prop('id');
        var parenttr = $(this).parents('tr');
        var nRow = $(this).parents('tr')[0];
        var info = "Are you sure you want to delete " + record + "?"; 
        modal.find('.modal-body p').text(info);
        modal.find('#button_delete_confirm').click(function() {
            table.row(nRow).remove().draw();
            modal.modal('hide');
            // trid = parenttr.attr('id');
            // If we want to turn it red add class 
            // parenttr.addClass('deletepending');
            // console.log('trid is' + trid);
        })
        modal.modal('show');
    });

    // handle edit button
    //$('.button_edit,.row_record').unbind().click(function(e) {
    $(document.body).on("click", ".button_edit,.row_record", function(e) {
        console.log('.button_edit, .row_record');
         e.stopPropagation();
         if ($(this).is('tr')) {
            var nRow = $(this)[0]; 
         } else {
            var nRow = $(this).parents('tr')[0];
         }
         var table = $("#tbl_records").DataTable();
        
        if (nEditing == nRow) {
            /* click on row already being edited, do nothing */
        } else if (nEditing !== null && nEditing != nRow && nNew == false) {
             /* Currently editing - but not this row - restore the old before continuing to edit mode */
             restoreRow(table, nEditing);
             editRow(table, nRow);
             nEditing = nRow;
         } else if (nNew == true) {
             /* adding a new row, delete it and start editing */
             table.row(nEditing).remove().draw();
             nNew = false;
             editRow(table, nRow);
             nEditing = nRow;
         } else {
             /* No edit in progress - let's start one */
             editRow(table, nRow);
             nEditing = nRow;
         }
         //onbuttonchange();
    });

    // handle cancel button
    //$('.button_cancel').unbind().click(function(e) {
    $(document.body).on("click", ".button_cancel", function(e) {
        console.log('.button_cancel');
        e.stopPropagation();
        var oTable = $("#tbl_records").DataTable();
        if (nNew) {
            oTable.row(nEditing).remove().draw();
            nEditing = null;
            nNew = false;
        } else {
            restoreRow(oTable, nEditing);
            nEditing = null;
        }
        //onbuttonchange();
    });

    //handle save button
    //$('.button_save').unbind().click(function(e) {
    $(document.body).on("click", ".button_save", function(e) {
        console.log('.button_save');
        e.stopPropagation();
        var table = $("#tbl_records").DataTable();
        saveRow(table, nEditing);
        nEditing = null;
        nNew = false;
        //onbuttonchange();
    });
//}


{% if record_helper_setting %}
//handle wacky record types
$(document.body).on("focus", "#current_edit_record_data", function (e) {
    console.log('#current_edit_record_data');
    var record_type = $(this).parents("tr").find('#record_type').val();
    var record_data = $(this);
    if (record_type == "MX") {
        var modal = $("#modal_custom_record");
        if (record_data.val() == "") {
            var form = "    <label for=\"mx_priority\">MX Priority</label> \
                            <input type=\"text\" class=\"form-control\" name=\"mx_priority\" id=\"mx_priority\" placeholder=\"eg. 10\"> \
                            <label for=\"mx_server\">MX Server</label> \
                            <input type=\"text\" class=\"form-control\" name=\"mx_server\" id=\"mx_server\" placeholder=\"eg. postfix.example.com\"> \
                        ";
        } else {
            var parts = record_data.val().split(" ");
            var form = "    <label for=\"mx_priority\">MX Priority</label> \
                            <input type=\"text\" class=\"form-control\" name=\"mx_priority\" id=\"mx_priority\" placeholder=\"eg. 10\" value=\"" + parts[0] + "\"> \
                            <label for=\"mx_server\">MX Server</label> \
                            <input type=\"text\" class=\"form-control\" name=\"mx_server\" id=\"mx_server\" placeholder=\"eg. postfix.example.com\" value=\"" + parts[1] + "\"> \
                        ";
        }
        modal.find('.modal-body p').html(form);
        modal.find('#button_save').click(function() {
            mx_server = modal.find('#mx_server').val();
            mx_priority = modal.find('#mx_priority').val();
            data = mx_priority + " " + mx_server;
            record_data.val(data);
            modal.modal('hide');
        })
        modal.modal('show');
    } else if (record_type == "SRV") {
        var modal = $("#modal_custom_record");
        if (record_data.val() == "") {
            var form = "    <label for=\"srv_priority\">SRV Priority</label> \
                            <input type=\"text\" class=\"form-control\" name=\"srv_priority\" id=\"srv_priority\" placeholder=\"0\"> \
                            <label for=\"srv_weight\">SRV Weight</label> \
                            <input type=\"text\" class=\"form-control\" name=\"srv_weight\" id=\"srv_weight\" placeholder=\"10\"> \
                            <label for=\"srv_port\">SRV Port</label> \
                            <input type=\"text\" class=\"form-control\" name=\"srv_port\" id=\"srv_port\" placeholder=\"5060\"> \
                            <label for=\"srv_target\">SRV Target</label> \
                            <input type=\"text\" class=\"form-control\" name=\"srv_target\" id=\"srv_target\" placeholder=\"sip.example.com\"> \
                        ";
        } else {
            var parts = record_data.val().split(" "); 
            var form = "    <label for=\"srv_priority\">SRV Priority</label> \
                            <input type=\"text\" class=\"form-control\" name=\"srv_priority\" id=\"srv_priority\" placeholder=\"0\" value=\"" + parts[0] + "\"> \
                            <label for=\"srv_weight\">SRV Weight</label> \
                            <input type=\"text\" class=\"form-control\" name=\"srv_weight\" id=\"srv_weight\" placeholder=\"10\" value=\"" + parts[1] + "\"> \
                            <label for=\"srv_port\">SRV Port</label> \
                            <input type=\"text\" class=\"form-control\" name=\"srv_port\" id=\"srv_port\" placeholder=\"5060\" value=\"" + parts[2] + "\"> \
                            <label for=\"srv_target\">SRV Target</label> \
                            <input type=\"text\" class=\"form-control\" name=\"srv_target\" id=\"srv_target\" placeholder=\"sip.example.com\" value=\"" + parts[3] + "\"> \
            ";
        }
        modal.find('.modal-body p').html(form);
        modal.find('#button_save').click(function() {
            srv_priority = modal.find('#srv_priority').val();
            srv_weight = modal.find('#srv_weight').val();
            srv_port = modal.find('#srv_port').val();
            srv_target = modal.find('#srv_target').val();
            data = srv_priority + " " + srv_weight + " " + srv_port + " " + srv_target;
            record_data.val(data);
            modal.modal('hide');
        })
        } else if (record_type == "SOA") {
            var modal = $("#modal_custom_record");
            if (record_data.val() == "") {
                var form = "    <label for=\"soa_primaryns\">Primary Name Server</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_primaryns\" id=\"soa_primaryns\" placeholder=\"ns1.example.com\"> \
                                <label for=\"soa_adminemail\">Primary Contact</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_adminemail\" id=\"soa_adminemail\" placeholder=\"admin.example.com\"> \
                                <label for=\"soa_serial\">Serial</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_serial\" id=\"soa_serial\" placeholder=\"2016010101\"> \
                                <label for=\"soa_zonerefresh\">Zone refresh timer</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_zonerefresh\" id=\"soa_zonerefresh\" placeholder=\"86400\"> \
                                <label for=\"soa_failedzonerefresh\">Failed refresh retry timer</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_failedzonerefresh\" id=\"soa_failedzonerefresh\" placeholder=\"7200\"> \
                                <label for=\"soa_zoneexpiry\">Zone expiry timer</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_zoneexpiry\" id=\"soa_zoneexpiry\" placeholder=\"604800\"> \
                                <label for=\"soa_minimumttl\">Minimum TTL</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_minimumttl\" id=\"soa_minimumttl\" placeholder=\"300\"> \
                            ";
            } else {
                var parts = record_data.val().split(" "); 
                var form = "    <label for=\"soa_primaryns\">Primary Name Server</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_primaryns\" id=\"soa_primaryns\" value=\"" + parts[0] + "\"> \
                                <label for=\"soa_adminemail\">Primary Contact</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_adminemail\" id=\"soa_adminemail\" value=\"" + parts[1] + "\"> \
                                <label for=\"soa_serial\">Serial</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_serial\" id=\"soa_serial\" value=\"" + parts[2] + "\"> \
                                <label for=\"soa_zonerefresh\">Zone refresh timer</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_zonerefresh\" id=\"soa_zonerefresh\" value=\"" + parts[3] + "\"> \
                                <label for=\"soa_failedzonerefresh\">Failed refresh retry timer</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_failedzonerefresh\" id=\"soa_failedzonerefresh\" value=\"" + parts[4] + "\"> \
                                <label for=\"soa_zoneexpiry\">Zone expiry timer</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_zoneexpiry\" id=\"soa_zoneexpiry\" value=\"" + parts[5] + "\"> \
                                <label for=\"soa_minimumttl\">Minimum TTL</label> \
                                <input type=\"text\" class=\"form-control\" name=\"soa_minimumttl\" id=\"soa_minimumttl\" value=\"" + parts[6] + "\"> \
                ";
            }
            modal.find('.modal-body p').html(form);
            modal.find('#button_save').click(function() {                   
                soa_primaryns = modal.find('#soa_primaryns').val();
                soa_adminemail = modal.find('#soa_adminemail').val();
                soa_serial = modal.find('#soa_serial').val();
                soa_zonerefresh = modal.find('#soa_zonerefresh').val();
                soa_failedzonerefresh = modal.find('#soa_failedzonerefresh').val();
                soa_zoneexpiry = modal.find('#soa_zoneexpiry').val();
                soa_minimumttl = modal.find('#soa_minimumttl').val();
                
                data = soa_primaryns + " " + soa_adminemail + " " + soa_serial + " " + soa_zonerefresh + " " + soa_failedzonerefresh + " " + soa_zoneexpiry + " " + soa_minimumttl;
                record_data.val(data);
                modal.modal('hide');
            })
        modal.modal('show');
    }
});
{% endif %}
</script>
{% endmacro %}
