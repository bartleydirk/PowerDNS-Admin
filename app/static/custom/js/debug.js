// Function to convert a form to object
function form_to_object(form_id) {
    var dataa = {};
    var str = '';
    $('#' + form_id + ' *').filter(':input').each(function(){
        if (this.name != '' ) {
            //console.log('form_to_object ' + this.name + ' ' + this.value);
            dataa[this.name] = this.value;
            str = str + " " + this.name + ": " + this.value;
        }
    });
    //if (form_id == 'jobdesteditform1_') { alert(str); }
    return dataa;
}
function form_to_object2(form_id) {
    var dataa = {};
    var str = '';
    debug = false;
    if (debug) { console.log('form_to_object2'); }
    $('#' + form_id + ' *').filter(':input').each(function(){
        if (this.name != '' ) {
            if($(this).is(':checkbox')) {
                if($(this).is(":checked")) {
                    if (debug) { console.log('form_to_object2 is checkbox ' + this.name + ' is checked'); }
                    dataa[this.name] = true;
                } else {
                    if (debug) { console.log('form_to_object2 is checkbox ' + this.name + ' is not checked'); }
                    dataa[this.name] = false;
                }
            } else if ($(this).is("input[type='radio']")) {
                if($(this).is(":checked")) {
                    if (debug) { console.log('form_to_object2 is radio ' + this.name + ' is checked'); }
                    dataa[this.name] = this.value;
                } else {
                    if (debug) { console.log('form_to_object2 is radio ' + this.name + ' is not checked'); }
                }
            } else if ($(this).is("select[multiple]")) {
                var lst = $('#' + this.id).val();
                if (lst !== null) {
                    console.log('select multiple found ' + this.name + ' ' + $('#' + this.id).val());
                    dataa[this.name] = lst;
                }
            } else {
                if (debug) { console.log('form_to_object2 else ' + this.name + ' ' + this.value); }
                dataa[this.name] = this.value;
                str = str + " " + this.name + ": " + this.value;
            }
        }
    });
    //if (form_id == 'jobdesteditform1_') { alert(str); }
    return dataa;
}
function object_to_debugstring(dta) {
    var str = '';
    for (var key in dta) {
        //console.log('object_to_debugstring key is "' + key + '"');
        if (dta.hasOwnProperty(key)) {
            if (typeof dta[key] === 'object') {
                for (var key2 in dta[key]) {
                    str = str + " " + key2 + " " + dta[key][key2];
                }
                str = str + "\n - "
            } else {
                str = str + " " + key + " " +dta[key];
            }
        }
    }
    return str;
}
// called by other functions
function jsobjects_combine(dta, dta2) {
    for (var key in dta2) {
        if (dta2.hasOwnProperty(key)) {
            dta[key] = dta2[key]
        }
    }
    return dta;
}
$.fn.serializeObject = function()
{
    var o = {};
    var a = this.serializeArray();
    $.each(a, function() {
        //console.log('serializeArray ' + this.name);
        if (o[this.name] !== undefined) {
            if (!o[this.name].push) {
                o[this.name] = [o[this.name]];
            }
            o[this.name].push(this.value || '');
        } else {
            o[this.name] = this.value || '';
        }
    });
    return o;
};
