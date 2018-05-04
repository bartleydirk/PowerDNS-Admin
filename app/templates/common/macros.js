{% macro manageuser() %}
// set up user data table
$("#tbl_users").DataTable({
    "paging" : true,
    "lengthChange" : false,
    "searching" : true,
    "ordering" : true,
    "info" : true,
    "autoWidth" : false
});

// handle revocation of privileges
$(document.body).on('click', '.button_revoke', function() {
    var modal = $("#modal_revoke");
    var username = $(this).prop('id');
    var info = "Are you sure you want to revoke all privileges for " + username + ". They will not able to access any domain."; 
    console.log('button_revoke username "' + username + '"')
    modal.find('.modal-body p').text(info);
    modal.find('#button_revoke_confirm').click(function() {
        var postdata = {'action': 'revoke_user_privielges', 'username': username}
        applyChanges_(postdata, '{{ url_for("admin_manageuser") }}', false, false)
        modal.modal('hide');
    })
    modal.modal('show');
});
// handle deletion of user
$(document.body).on('click', '.button_delete', function() {
    var modal = $("#modal_delete");
    var username = $(this).prop('id');
    var info = "Are you sure you want to delete " + username + "?";
    console.log('button_delete username "' + username + '"')
    modal.find('.modal-body p').text(info);
    modal.find('#button_delete_confirm').click(function() {
        var postdata = {'action': 'delete_user', 'username': username}
        applyChanges_(postdata, '{{ url_for("admin_manageuser") }}', false, true)
        modal.modal('hide');
    })
    modal.modal('show');
});

// initialize pretty checkboxes
$('.admin_toggle').iCheck({
    checkboxClass : 'icheckbox_square-blue',
    increaseArea : '20%' // optional
});

// handle checkbox toggling
$(document.body).on('ifToggled', '.admin_toggle', function() {
    var is_admin = $(this).prop('checked');
    var username = $(this).prop('id');
    console.log('ifToggled username "' + username + '" is_admin "' + is_admin + '"')
    postdata = {
        'action' : 'set_admin',
        'username' : username,
        'is_admin' : is_admin
    };
    applyChanges_(postdata, '{{ url_for("admin_manageuser") }}', false, false)
});
{% endmacro %}


{% macro userprofile() %}
$(function() {
    $('#tabs').tabs({
        // add url anchor tags
        activate: function(event, ui) {
            window.location.hash = ui.newPanel.attr('id');
        }
    });
    // re-set active tab (ui)
    var activeTabIdx = $('#tabs').tabs('option','active');
    $('#tabs li:eq('+activeTabIdx+')').tab('show')
});

// initialize pretty checkboxes
$('.otp_toggle').iCheck({
    checkboxClass : 'icheckbox_square-blue',
    increaseArea : '20%'
});

// handle checkbox toggling
$('.otp_toggle').on('ifToggled', function(event) {
    var enable_otp = $(this).prop('checked');
    var username = $(this).prop('id');
    postdata = {
        'action' : 'enable_otp',
        'data' : {
            'enable_otp' : enable_otp
        }
    };
    applyChanges(postdata, $SCRIPT_ROOT + '/user/profile');
    location.reload();
});
{% endmacro %}
