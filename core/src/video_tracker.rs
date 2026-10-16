
use opencv::core::{Mat, Rect, Scalar, Size, Vector};
use opencv::highgui;
use opencv::imgproc;
use opencv::objdetect::HOGDescriptor;
use opencv::prelude::*;
use opencv::videoio::{self, VideoCapture};
use std::env;
use std::thread;
use std::time::{Duration, Instant};

const NOME_JANELA: &str = "RedFox - Monitoramento";
const LARGURA_DETECCAO: i32 = 640;
const ALTURA_DETECCAO: i32 = 360;
const MAX_FALHAS_LEITURA: u32 = 10;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    // marca quantidade de detecções
    let mut deteccoes = 0;

    // Obtém a URL do stream pela variável de ambiente.
    let url = env::var("RTSP_URL")
        .expect("Defina a variável de ambiente RTSP_URL");

    // Abre a câmera RTSP usando FFmpeg.
    let mut cap =
        VideoCapture::from_file(&url, videoio::CAP_FFMPEG)?;

    if !cap.is_opened()? {
        return Err("Não foi possível abrir o stream RTSP".into());
    }

    // Inicializa o HOG com o classificador padrão de pessoas.
    let mut hog = HOGDescriptor::default()?;
    hog.set_svm_detector(
        HOGDescriptor::get_default_people_detector()?,
    );

    // Região monitorada: [x inicial, y inicial, x final, y final].
    let roi_normalizada = [0.2_f64, 0.2_f64, 0.8_f64, 0.8_f64];

    // Parâmetros do HOG.
    let stride = Size::new(4, 4);
    let padding = Size::new(16, 16);
    let escala = 1.05;
    let hit_threshold = 0.4; // o mais próximo de identificação porém se a pessoa estiver de lado fica difícil
    let limiar_final = 3.0;

    // Controle do intervalo entre alertas.
    let intervalo_alerta = Duration::from_secs(5);
    let mut ultimo_alerta: Option<Instant> = None;

    // Controle de falhas na leitura.
    let mut falhas_leitura = 0_u32;

    // inicia o módulo para abrir a janela com a imagem sendo capturada em tempo real
    highgui::named_window(NOME_JANELA, highgui::WINDOW_NORMAL)?;

    println!("Conectado ao stream RTSP: {}", url);
    println!("Pressione Q na janela para encerrar.");

    loop {
        let mut frame = Mat::default();

        // Captura o próximo frame.
        let leitura_ok = cap.read(&mut frame)?;

        if !leitura_ok || frame.empty() {
            falhas_leitura += 1;

            eprintln!(
                "Falha na leitura do frame ({}/{})",
                falhas_leitura, MAX_FALHAS_LEITURA
            );

            if falhas_leitura >= MAX_FALHAS_LEITURA {
                eprintln!("Limite de falhas atingido. Encerrando.");
                break;
            }

            thread::sleep(Duration::from_millis(200));
            continue;
        }

        falhas_leitura = 0;

        // Resolução real do vídeo exibido.
        let largura = frame.cols();
        let altura = frame.rows();

        if largura <= 0 || altura <= 0 {
            continue;
        }

        // Calcula a região monitorada na resolução original.
        let x1 = (roi_normalizada[0] * largura as f64)
            .round() as i32;
        let y1 = (roi_normalizada[1] * altura as f64)
            .round() as i32;
        let x2 = (roi_normalizada[2] * largura as f64)
            .round() as i32;
        let y2 = (roi_normalizada[3] * altura as f64)
            .round() as i32;

        let x1 = x1.clamp(0, largura);
        let y1 = y1.clamp(0, altura);
        let x2 = x2.clamp(x1, largura);
        let y2 = y2.clamp(y1, altura);

        let roi = Rect::new(
            x1,
            y1,
            x2 - x1,
            y2 - y1,
        );

        // Reduz a imagem usada na detecção.
        let mut frame_reduzido = Mat::default();

        imgproc::resize(
            &frame,
            &mut frame_reduzido,
            Size::new(LARGURA_DETECCAO, ALTURA_DETECCAO),
            0.0,
            0.0,
            imgproc::INTER_LINEAR,
        )?;

        // Detecta pessoas na imagem reduzida.
        let mut deteccoes_reduzidas = Vector::<Rect>::new();

        hog.detect_multi_scale(
            &frame_reduzido,
            &mut deteccoes_reduzidas,
            hit_threshold,
            stride,
            padding,
            escala,
            limiar_final,
            false,
        )?;

        // Converte as coordenadas para a resolução original.
        let fator_x = largura as f64 / LARGURA_DETECCAO as f64;
        let fator_y = altura as f64 / ALTURA_DETECCAO as f64;

        let mut pessoa_na_roi = false;

        for det in deteccoes_reduzidas.iter() {
            let px1 = (det.x as f64 * fator_x).round() as i32;
            let py1 = (det.y as f64 * fator_y).round() as i32;
            let px2 = ((det.x + det.width) as f64 * fator_x)
                .round() as i32;
            let py2 = ((det.y + det.height) as f64 * fator_y)
                .round() as i32;

            // Limita a caixa de detecção à imagem original.
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

            // Calcula a interseção entre a detecção e a ROI.
            let inter_x1 = pessoa.x.max(roi.x);
            let inter_y1 = pessoa.y.max(roi.y);
            let inter_x2 = (pessoa.x + pessoa.width)
                .min(roi.x + roi.width);
            let inter_y2 = (pessoa.y + pessoa.height)
                .min(roi.y + roi.height);

            let inter_largura = (inter_x2 - inter_x1).max(0);
            let inter_altura = (inter_y2 - inter_y1).max(0);

            let area_intersecao =
                inter_largura as i64 * inter_altura as i64;

            let area_pessoa =
                pessoa.width as i64 * pessoa.height as i64;

            // Considera relevante uma sobreposição de pelo menos 20%.
            if area_pessoa > 0
                && area_intersecao as f64 / area_pessoa as f64 >= 0.20
            {
                pessoa_na_roi = true;
            }

            // Desenha as detecções em verde.
            imgproc::rectangle(
                &mut frame,
                pessoa,
                Scalar::new(0.0, 255.0, 0.0, 0.0),
                2,
                imgproc::LINE_8,
                0,
            )?;
        }

        // Desenha a região monitorada em vermelho.
        imgproc::rectangle(
            &mut frame,
            roi,
            Scalar::new(0.0, 0.0, 255.0, 0.0),
            2,
            imgproc::LINE_8,
            0,
        )?;

        // Mostra o vídeo com as detecções.
        highgui::imshow(NOME_JANELA, &frame)?;

        // Atualiza a janela e verifica se Q foi pressionado.
        let tecla = highgui::wait_key(1)?;

        if tecla == i32::from(b'q') || tecla == i32::from(b'Q') {
            break;
        }

        // Emite alertas respeitando o intervalo configurado.
        if pessoa_na_roi {
            let agora = Instant::now();

            let pode_alertar = ultimo_alerta
                .map(|instante| instante.elapsed() >= intervalo_alerta)
                .unwrap_or(true);

            if pode_alertar {
                deteccoes += 1;
                println!(
                    "ALERTA: pessoa detectada na região monitorada: {}", deteccoes.to_string()
                );
                ultimo_alerta = Some(agora);
            }
        }
    }

    // Fecha a janela e libera a captura.
    highgui::destroy_window(NOME_JANELA)?;
    cap.release()?;

    Ok(())
}
