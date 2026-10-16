use opencv::core::{Mat, Point, Rect, Scalar, Size, Vector};
use opencv::highgui;
use opencv::imgproc;
use opencv::objdetect::HOGDescriptor;
use opencv::prelude::*;
use opencv::videoio::{self, VideoCapture};

use serde::Deserialize;
use std::env;
use std::fs;
use std::thread;
use std::time::{Duration, Instant};

const NOME_JANELA: &str = "RedFox - Monitoramento";
const LARGURA_DETECCAO: i32 = 640;
const ALTURA_DETECCAO: i32 = 480;
const MAX_FALHAS_LEITURA: u32 = 10;
const ARQUIVO_ROI: &str = "redfox-roi.json";

// Estrutura de um ponto do JSON.
#[derive(Debug, Deserialize)]
struct PontoConfig {
    x: i32,
    y: i32,
}

// Estrutura de uma ROI retangular.
#[derive(Debug, Deserialize)]
struct RetanguloConfig {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

// Estrutura principal da configuração.
#[derive(Debug, Deserialize)]
struct RoiConfig {
    #[serde(rename = "type")]
    tipo: String,

    image_width: i32,
    image_height: i32,

    #[serde(default)]
    closed: bool,

    #[serde(default)]
    points: Vec<PontoConfig>,

    #[serde(default)]
    roi: Option<RetanguloConfig>,
}

// Carrega a configuração e converte tudo para um polígono.
fn carregar_roi(
    caminho: &str,
) -> Result<(Vec<Point>, i32, i32), Box<dyn std::error::Error>> {
    let conteudo = fs::read_to_string(caminho)?;

    let config: RoiConfig = serde_json::from_str(&conteudo)?;

    if config.image_width <= 0 || config.image_height <= 0 {
        return Err("Dimensões inválidas no JSON da ROI".into());
    }

    let pontos: Vec<Point> = match config.tipo.as_str() {
        "polygon" => {
            if config.points.len() < 3 {
                return Err(
                    "O polígono precisa conter pelo menos três pontos".into()
                );
            }

            config.points
                .iter()
                .map(|p| Point::new(p.x, p.y))
                .collect()
        }

        "rectangle" => {
            let r = config.roi
                .ok_or("O JSON do retângulo não contém o campo roi")?;

            if r.width <= 0 || r.height <= 0 {
                return Err("A largura e a altura da ROI devem ser positivas".into());
            }

            vec![
                Point::new(r.x, r.y),
                Point::new(r.x + r.width, r.y),
                Point::new(r.x + r.width, r.y + r.height),
                Point::new(r.x, r.y + r.height),
            ]
        }

        outro => {
            return Err(
                format!("Tipo de ROI não suportado: {}", outro).into()
            );
        }
    };

    if pontos.len() < 3 {
        return Err(
            "A ROI precisa conter pelo menos três pontos".into()
        );
    }

    // Valida os pontos para evitar coordenadas negativas
    // ou fora da imagem de referência.
    for p in &pontos {
        if p.x < 0
            || p.y < 0
            || p.x > config.image_width
            || p.y > config.image_height
        {
            return Err(
                format!(
                    "Ponto ({}, {}) fora dos limites da imagem configurada",
                    p.x, p.y
                ).into()
            );
        }
    }

    Ok((
        pontos,
        config.image_width,
        config.image_height,
    ))
}

// Teste geométrico: verifica se um ponto está dentro do polígono.
fn ponto_dentro_poligono(
    ponto: Point,
    poligono: &[Point],
) -> bool {
    let mut dentro = false;
    let mut j = poligono.len() - 1;

    for i in 0..poligono.len() {
        let a = poligono[i];
        let b = poligono[j];

        if (a.y > ponto.y) != (b.y > ponto.y) {
            let cruzamento_x =
                (b.x - a.x) as f64
                * (ponto.y - a.y) as f64
                / (b.y - a.y) as f64
                + a.x as f64;

            if (ponto.x as f64) < cruzamento_x {
                dentro = !dentro;
            }
        }

        j = i;
    }

    dentro
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut deteccoes = 0;

    // URL do stream RTSP.
    let url = env::var("RTSP_URL")
        .expect("Defina a variável de ambiente RTSP_URL");

    // Carrega a região de interesse do JSON.
    let (roi_original, roi_largura_ref, roi_altura_ref) =
        carregar_roi(ARQUIVO_ROI)?;

    println!(
        "ROI carregada de {}: {} pontos",
        ARQUIVO_ROI,
        roi_original.len()
    );

    // Abre o stream RTSP.
    let mut cap =
        VideoCapture::from_file(&url, videoio::CAP_FFMPEG)?;

    if !cap.is_opened()? {
        return Err("Não foi possível abrir o stream RTSP".into());
    }

    // Inicializa o detector HOG.
    let mut hog = HOGDescriptor::default()?;

    hog.set_svm_detector(
        HOGDescriptor::get_default_people_detector()?,
    );

    // Parâmetros do HOG.
    let stride = Size::new(4, 4);
    let padding = Size::new(16, 16);
    let escala = 1.05;
    let hit_threshold = 0.3;
    let limiar_final = 3.0;

    // Controle dos alertas.
    let intervalo_alerta = Duration::from_secs(5);
    let mut ultimo_alerta: Option<Instant> = None;

    let mut falhas_leitura = 0_u32;

    highgui::named_window(
        NOME_JANELA,
        highgui::WINDOW_NORMAL,
    )?;

    println!("Conectado ao stream RTSP: {}", url);
    println!("Pressione Q na janela para encerrar.");

    loop {
        let mut frame = Mat::default();

        let leitura_ok = cap.read(&mut frame)?;

        if !leitura_ok || frame.empty() {
            falhas_leitura += 1;

            eprintln!(
                "Falha na leitura do frame ({}/{})",
                falhas_leitura,
                MAX_FALHAS_LEITURA
            );

            if falhas_leitura >= MAX_FALHAS_LEITURA {
                eprintln!("Limite de falhas atingido. Encerrando.");
                break;
            }

            thread::sleep(Duration::from_millis(200));
            continue;
        }

        falhas_leitura = 0;

        let largura = frame.cols();
        let altura = frame.rows();

        if largura <= 0 || altura <= 0 {
            continue;
        }

        // Escala os vértices do JSON para a resolução real da câmera.
        let roi: Vec<Point> = roi_original
            .iter()
            .map(|p| {
                Point::new(
                    ((p.x as f64 * largura as f64)
                        / roi_largura_ref as f64)
                        .round() as i32,

                    ((p.y as f64 * altura as f64)
                        / roi_altura_ref as f64)
                        .round() as i32,
                )
            })
            .collect();

        // Reduz a imagem para a detecção.
        let mut frame_reduzido = Mat::default();

        imgproc::resize(
            &frame,
            &mut frame_reduzido,
            Size::new(
                LARGURA_DETECCAO,
                ALTURA_DETECCAO,
            ),
            0.0,
            0.0,
            imgproc::INTER_LINEAR,
        )?;

        // Conversão para tons de cinza.
        let mut gray = Mat::default();

        imgproc::cvt_color(
            &frame_reduzido,
            &mut gray,
            imgproc::COLOR_BGR2GRAY,
            0,
        )?;

        // Detecta pessoas.
        let mut deteccoes_reduzidas =
            Vector::<Rect>::new();

        hog.detect_multi_scale(
            &gray,
            &mut deteccoes_reduzidas,
            hit_threshold,
            stride,
            padding,
            escala,
            limiar_final,
            false,
        )?;

        // Fatores para voltar à resolução original.
        let fator_x =
            largura as f64 / LARGURA_DETECCAO as f64;

        let fator_y =
            altura as f64 / ALTURA_DETECCAO as f64;

        let mut pessoa_na_roi = false;

        for det in deteccoes_reduzidas.iter() {
            let px1 =
                (det.x as f64 * fator_x).round() as i32;

            let py1 =
                (det.y as f64 * fator_y).round() as i32;

            let px2 =
                ((det.x + det.width) as f64 * fator_x)
                    .round() as i32;

            let py2 =
                ((det.y + det.height) as f64 * fator_y)
                    .round() as i32;

            let px1 = px1.clamp(0, largura);
            let py1 = py1.clamp(0, altura);
            let px2 = px2.clamp(px1, largura);
            let py2 = py2.clamp(py1, altura);

            let pessoa = Rect::new(
                px1,
                py1,
                px2 - px1,
                py2 - py1,
            );

            // Usa o centro inferior da caixa como referência
            // para verificar se a pessoa está na região.
            let ponto_referencia = Point::new(
                pessoa.x + pessoa.width / 2,
                pessoa.y + pessoa.height,
            );

            if ponto_dentro_poligono(
                ponto_referencia,
                &roi,
            ) {
                pessoa_na_roi = true;
            }

            // Desenha a detecção em verde.
            imgproc::rectangle(
                &mut frame,
                pessoa,
                Scalar::new(0.0, 255.0, 0.0, 0.0),
                2,
                imgproc::LINE_8,
                0,
            )?;

            // Marca o ponto de referência da pessoa.
            imgproc::circle(
                &mut frame,
                ponto_referencia,
                4,
                Scalar::new(255.0, 255.0, 0.0, 0.0),
                -1,
                imgproc::LINE_8,
                0,
            )?;
        }

        // Desenha o polígono fechado em vermelho.
        for i in 0..roi.len() {
            let atual = roi[i];
            let proximo = roi[(i + 1) % roi.len()];

            imgproc::line(
                &mut frame,
                atual,
                proximo,
                Scalar::new(0.0, 0.0, 255.0, 0.0),
                2,
                imgproc::LINE_8,
                0,
            )?;
        }

        // Converte o frame anotado para tons de cinza.
        let mut frame_exibicao = Mat::default();

        imgproc::cvt_color(
            &frame,
            &mut frame_exibicao,
            imgproc::COLOR_BGR2GRAY,
            0,
        )?;

        highgui::imshow(
            NOME_JANELA,
            &frame_exibicao,
        )?;

        let tecla = highgui::wait_key(1)?;

        if tecla == i32::from(b'q')
            || tecla == i32::from(b'Q')
        {
            break;
        }

        // Emite alertas respeitando o intervalo configurado.
        if pessoa_na_roi {
            let agora = Instant::now();

            let pode_alertar = ultimo_alerta
                .map(|instante| {
                    instante.elapsed() >= intervalo_alerta
                })
                .unwrap_or(true);

            if pode_alertar {
                deteccoes += 1;

                println!(
                    "ALERTA: pessoa detectada na região monitorada: {}",
                    deteccoes
                );

                ultimo_alerta = Some(agora);
            }
        }
    }

    highgui::destroy_window(NOME_JANELA)?;
    cap.release()?;

    Ok(())
}
