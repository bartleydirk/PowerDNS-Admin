
{% macro domainqueryjs() %}
function reload_domains() {
    frmdata = form_to_object2('domain_query_frm');
    console.log('reload_domains frmdata ' + object_to_debugstring(frmdata));
    $.ajax({
        url: '{{ url_for("query_domain_reload") }}',
        type: "post",
        data: frmdata,
        datatype: 'html',
        success: function(data){
            console.log('query_domain_reload in success from table');
            $('#domain_content_div').html(data);
        }
    });
}
{% endmacro %}
