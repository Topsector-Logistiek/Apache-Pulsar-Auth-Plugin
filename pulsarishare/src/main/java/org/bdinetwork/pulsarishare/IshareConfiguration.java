package org.bdinetwork.pulsarishare;

import org.apache.pulsar.broker.ServiceConfiguration;

public class IshareConfiguration {

    private ServiceConfiguration conf;

    public static final String CONF_ISHARE_SATELLITE_ID = "ishareSatelliteId";
    public static final String CONF_ISHARE_SATELLITE_URL = "ishareSatelliteUrl";
    public static final String CONF_ISHARE_SERVICE_PROVIDER_ID = "ishareServiceProviderId";
    public static final String CONF_ISHARE_SERVICE_PROVIDER_CERTIFICATE = "ishareServiceProviderCertificate";
    public static final String CONF_ISHARE_SERVICE_PROVIDER_PRIVATE_KEY = "ishareServiceProviderPrivateKey";
    public static final String CONF_ISHARE_AUTHORIZATION_REGISTRY_ID = "ishareAuthorizationRegistryId";
    public static final String CONF_ISHARE_AUTHORIZATION_REGISTRY_URL = "ishareAuthorizationRegistryUrl";
    
    public static final String CONF_ISHARE_CONCEPT = "ishareConcept";
    public static final String CONF_ISHARE_ACTION_PREFIX = "ishareActionPrefix";
    
    public IshareConfiguration(ServiceConfiguration configuration){
        this.conf = configuration;
    }

    public Object getProperty(String key) {
        return conf.getProperty(key);
     }

    public String getSatelliteId() {
        return (String) conf.getProperty(CONF_ISHARE_SATELLITE_ID);
    }
    public String getSatelliteUrl() {
        return (String) conf.getProperty(CONF_ISHARE_SATELLITE_URL);
    }
    public String getServiceProviderId() {
        return (String) conf.getProperty(CONF_ISHARE_SERVICE_PROVIDER_ID);
    }
    public String getServiceProviderCertificate() {
        return (String) conf.getProperty(CONF_ISHARE_SERVICE_PROVIDER_CERTIFICATE);
    }
    public String getServiceProviderPrivateKey() {
        return (String) conf.getProperty(CONF_ISHARE_SERVICE_PROVIDER_PRIVATE_KEY);
    }
    public String getAuthorizationRegistryId() {
        return (String) conf.getProperty(CONF_ISHARE_AUTHORIZATION_REGISTRY_ID);
    }
    public String getAuthorizationRegistryUrl() {
        return (String) conf.getProperty(CONF_ISHARE_AUTHORIZATION_REGISTRY_URL);
    }    
    

    public String getConcept() {
        return (String) conf.getProperty(CONF_ISHARE_CONCEPT);
    }
    public String getActionPrefix() {
        return (String) conf.getProperty(CONF_ISHARE_ACTION_PREFIX);
    }


    




}
