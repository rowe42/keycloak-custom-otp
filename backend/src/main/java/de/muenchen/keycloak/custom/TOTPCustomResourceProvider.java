package de.muenchen.keycloak.custom;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import org.jboss.logging.Logger;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import java.util.Set;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;



public class TOTPCustomResourceProvider implements RealmResourceProvider {

    protected static final Logger LOG = Logger.getLogger(TOTPCustomResourceProvider.class);
    private final KeycloakSession session;
    private AuthenticationManager.AuthResult auth;

    public TOTPCustomResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    
    @POST
    @Produces("application/json")
    public TOTPResponse post(TOTPRequest totpRequest)  {
        KeycloakContext context = session.getContext();
        
        //check if current user is authenticated and authorized (checks berer token)
        auth = new AppAuthManager().authenticateBearerToken(session, session.getContext().getRealm());
        checkAdmin();

        //check inputs
        String username = totpRequest.getUsername();
        String targetRealmName = totpRequest.getRealm();
        if (username == null) {
            LOG.error("Username missing!");
            throw new BadRequestException("Username missing!");
        } else if (targetRealmName == null) {
            LOG.error("Target realm missing!");
            throw new BadRequestException("Target realm missing!");
        }

        //find realm where user with new otp should be
        RealmModel targetRealm = session.realms().getRealmByName(totpRequest.getRealm());
        if (targetRealm == null) {
            throw new BadRequestException("Realm missing or wrong!");
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
    
    private void checkAdmin() {
        if (auth == null) {
            LOG.error("No Bearer token found or token not valid");
            throw new NotAuthorizedException("Bearer");
        }
        
        LOG.info("roleMappings of current user:");
        logRoles(auth.getUser().getRoleMappings());
        LOG.info("realmRoleMappings of current user:");
        logRoles(auth.getUser().getRealmRoleMappings());
        
        if (!userHasRole(auth.getUser().getRoleMappings(), "admin") && //global admin
                !userHasRole(auth.getUser().getRealmRoleMappings(), "manage-users")) { //local admin for users
            throw new ForbiddenException("Does not have global admin role or ream role manage-users");
        }
    }

    private boolean userHasRole(Set<RoleModel> roleMappings, String role) {
        if (roleMappings == null) return false;
        
        for (RoleModel roleModel : roleMappings) {
            if (roleModel.getName().equals(role)) {
                return true;
            }
        }
        return false;
    }
    
    private void logRoles(Set<RoleModel> roleMappings) {
        for (RoleModel roleModel : roleMappings) {
            LOG.info(roleModel.getName());
        }
    }
}
