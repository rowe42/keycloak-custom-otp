package de.muenchen.keycloak.custom;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import org.jboss.logging.Logger;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;



public class TOTPCustomResourceProvider extends AdminRoot implements RealmResourceProvider {

    protected static final Logger LOG = Logger.getLogger(TOTPCustomResourceProvider.class);

    public TOTPCustomResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    
    @POST
    @Produces("application/json")
    public TOTPResponse post(@Context final HttpHeaders headers, TOTPRequest totpRequest)  {
        KeycloakContext context = session.getContext();
        RealmModel targetRealm = context.getRealm(); //schon hier abholen; context.getRealm ändert sich nach Aufruf von authenticateRealmAdminRequest!
        
        //check if current user is authenticated and authorized (checks bearer token)        
        AdminAuth auth = authenticateRealmAdminRequest(headers);
        if (!AdminPermissions.realms(session, auth).isAdmin(targetRealm)) {
            LOG.error("User with given Access Token is not admin for realm " +targetRealm.getName());
            throw new ForbiddenException();
        }

        //check inputs
        String username = totpRequest.getUsername();
        if (username == null) {
            LOG.error("Username missing!");
            throw new BadRequestException("Username missing!");
        } 
        
        //search user in DB in target realm
        LOG.info("Searching user in Realm " + targetRealm.getName() + " with username " + username);
        UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, targetRealm, username);
        if (user == null) {
            LOG.error("User not found!");
            throw new BadRequestException("User not found!");
        }
        
        //generate secret for target user in target realm
        TotpBean totpBean = new TotpBean(session, targetRealm, user, context.getUri().getRequestUriBuilder());
        String totpSecret = totpBean.getTotpSecret();
        String totpSecretQrCode = totpBean.getTotpSecretQrCode();
        
        //store otp secret as new credentials for target user
        UserCredentialModel credentials = new UserCredentialModel();
        credentials.setType(targetRealm.getOTPPolicy().getType());
        credentials.setValue(totpSecret);
        session.userCredentialManager().updateCredential(targetRealm, user, credentials);
        
        //If CONFIGURE_OTP Required Action exists for target user, remove it (gets added if user tries to login without otp)
        if (user.getRequiredActions().contains(UserModel.RequiredAction.CONFIGURE_TOTP.name())) {
            LOG.info("Remove required action CONFIGURE_TOTP of user " + user.getUsername());
            user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP.name());
        }

        //generate response
        TOTPResponse totpResponse = new TOTPResponse();
        totpResponse.setSecret(totpSecret);
        totpResponse.setSecretQrcode(totpSecretQrCode);
        return totpResponse;
    }

    @Override
    public void close() {
    }
    
}
