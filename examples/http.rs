use std::thread::sleep;
use std::{io, time::Duration};

use clap::Parser;
use log::{error, info};
use rcgen::{Certificate, CertificateParams, DistinguishedName};

use small_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opts = Options::parse();

    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Staging.url(),
        None,
    )?;

    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.

    let identifier = Identifier::Dns(opts.name);
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .unwrap();

    let state = order.state();
    info!("order state: {:#?}", state);
    assert!(matches!(state.status, OrderStatus::Pending));

    // Pick the desired challenge type and prepare the response.

    let authorizations = order.authorizations().unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("no http01 challenge found"))?;

        let Identifier::Dns(identifier) = &authz.identifier;

        println!(
            "Please set the following content in a file at \
            '/.well-known/acme-challenge/{}', then press any key:",
            challenge.token
        );
        println!("{}", order.key_authorization(challenge).as_str());
        io::stdin().read_line(&mut String::new()).unwrap();

        challenges.push((identifier, &challenge.url));
    }

    // Let the server know we're ready to accept the challenges.

    for (_, url) in &challenges {
        order.set_challenge_ready(url).unwrap();
    }

    // Exponentially back off until the order becomes ready or invalid.

    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    let state = loop {
        sleep(delay);
        order.refresh().unwrap();
        let state = order.state();
        if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
            info!("order state: {:#?}", state);
            break state;
        }

        delay *= 2;
        tries += 1;
        match tries < 5 {
            true => info!("order is not ready, waiting {delay:?} {state:?} {tries}"),
            false => {
                error!("order is not ready {state:?} {tries}");
                return Err(anyhow::anyhow!("order is not ready"));
            }
        }
    };

    if state.status == OrderStatus::Invalid {
        return Err(anyhow::anyhow!("order is invalid"));
    }

    let mut names = Vec::with_capacity(challenges.len());
    for (identifier, _) in challenges {
        names.push(identifier.to_owned());
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.

    let mut params = CertificateParams::new(names.clone());
    params.distinguished_name = DistinguishedName::new();
    let cert = Certificate::from_params(params).unwrap();
    let csr = cert.serialize_request_der()?;

    // Finalize the order and print certificate chain, private key and account credentials.

    order.finalize(&csr).unwrap();
    tries = 0;
    let cert_chain_pem = loop {
        match order.certificate().unwrap() {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)),
        }
        tries += 1;
        if tries > 10 {
            panic!("No cert received");
        }
    };
    info!("certficate chain:\n\n{:?}", cert_chain_pem,);
    info!("private key:\n\n{}", cert.serialize_private_key_pem());
    info!(
        "account credentials:\n\n{}",
        serde_json::to_string_pretty(&credentials).unwrap()
    );

    Ok(())
}

#[derive(Parser)]
struct Options {
    #[clap(long)]
    name: String,
}
