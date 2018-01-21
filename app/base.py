"""
Base Classes
"""
from flask.ext.admin import BaseView
from flask.ext import login

class BaipyBaseView(BaseView):
    """ Class to override BaseView, so I can pass style, curls, dblink to all the views of the child subclass """
    @login.login_required
    def is_accessible(self):
        """ Use This applications authenticated to determine if accessible """
        return login.current_user.is_authenticated()

    def render(self, template, **kwags):
        """ Add curruser, curls, dblink and dbmenu to what gets passed back to the views"""
        if login.current_user.is_anonymous:
            session['toUrl'] = request.url
            return redirect(url_for('login_view'))

        return super(BaipyBaseView, self).render(template, curruser=login.current_user, curls=curls,
                                                 dblink=dblinkurl(request), **kwags)
