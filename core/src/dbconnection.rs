use mysql::{params, prelude::*, Pool};

// busca pelo prefixo de macaddress no banco de dados para identificar
// o fabricante do dispositivo
pub fn check_mac_prefix(mac_address: &str) -> mysql::Result<String> {
    // url de conexão
    let url = "mysql://cvant:k6jg2210-30@127.0.0.1:3306/cvant";
    // cria o pool para receber a conexão do MySQL
    let pool = Pool::new(url)?;
    // cria a conexão 
    let mut conn = pool.get_conn()?;
    // converter o mac address para UCASE
    let mac_address = mac_address.to_uppercase();
    // mac slice
    let mac_prefix: &str = &mac_address[0..8];
    // monta a query
    let query_sql = format!("SELECT mac_vendor FROM prefixes WHERE mac_prefix='{mac_prefix}' limit 1");
    // executa a query retornando valores do resultado por isso o .query
    let mac_vendor: Vec<String> = conn.query(query_sql,)?;

    // converte o mac_vendor
    let mac_factory = match mac_vendor.first() {
        Some(vendor) => vendor.clone(),
        None => "Unknown".to_string(),
    };

    Ok(mac_factory)
}


// insere no banco de dados a máquina encontrada com o respectivo fabricante e macadress
pub fn insert_arp_table(ip_addr: &str, mac_addr: &str, vendor: &str, timestamp: &str) -> mysql::Result<()> {
    // url de conexão
    let url = "mysql://cvant:k6jg2210-30@127.0.0.1:3306/cvant";
    // cria o pool para receber a conexão do MySQL
    let pool = Pool::new(url)?;
    // cria a conexão 
    let mut conn = pool.get_conn()?;
    // é camera ? false
    let is_camera = "false";
    // executa a query porém SEM RETORNAR nada do resultado, por isso o .exec_drop
    conn.exec_drop("INSERT INTO arptable (ip_addr, mac_addr, vendor, timestamp) VALUES (:ip_addr, :mac_addr, :vendor, :timestamp)",
    mysql::params!{"ip_addr" => ip_addr,"mac_addr" => mac_addr,"vendor" => vendor,"timestamp" => timestamp},)?;

    Ok(())
}




// insere dados de log no banco de dados
pub fn insert_log_information(event_function: &str, event_description: &str, timestamp: &str) -> mysql::Result<()> {
    //url da conexão
    let url = "mysql://cvant:k6jg2210-30@127.0.0.1:3306/cvant";
    // cria o pool para receber a conexão do MySQL
    let pool = Pool::new(url)?;
    // cria objeto de conexão
    let mut conn = pool.get_conn()?;

    conn.exec_drop("INSERT INTO logtable (event_function, event_description, timestamp) VALUES (:event_function, :event_description, :timestamp)",
    mysql::params!{"event_function" => event_function, "event_description" => event_description, "timestamp" => timestamp,})?;

    Ok(())
}
