use encoding_rs::EUC_KR;
use maplit::hashmap;
use rpassword::prompt_password_stdout;
use std::error::Error;
use std::io::{stdin, stdout, Read, Write};
use tempfile::tempdir;
use text_template::Template;

const MAPLESTORY_REG_KEY: &str = r#"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Wizet\MapleStory"#;
const ZANDAM_WASM: &[u8] = include_bytes!("../../zandam/pkg/zandam_bg.wasm");
const ZANDAM_JS: &str = include_str!("../../zandam/pkg/zandam.js");
const HTML_TEMPLATE: &str = include_str!("../template.html");

fn decode_maybe_euckr(x: Vec<u8>) -> String {
    match String::from_utf8(x.clone()) {
        Ok(s) => s,
        Err(_) => {
            let (cow, _enc_used, had_errors) = EUC_KR.decode(&x);
            if had_errors {
                panic!("해당 문자열을 UTF-8 또는 EUC-KR로 해석할 수 없습니다. (손상된 데이터일 수 있음)");
            }
            cow.to_string()
        }
    }
}

fn main() {
    match std::panic::catch_unwind(main_) {
        Ok(Ok(())) => (),
        Ok(Err(e)) => {
            println!("오류 발생: {}", e);
            println!("<엔터>를 누르면 프로그램이 종료됩니다.");
            stdout().flush().unwrap();
            stdin().lock().read(&mut [0]).unwrap();
        }
        Err(_) => {
            println!(
                "복구 불가능한 오류가 발생하였습니다. 개발자에게 위 내용을 복사해 전달해 주세요."
            );
            println!("<엔터>를 누르면 프로그램이 종료됩니다.");
            stdout().flush().unwrap();
            stdin().read(&mut [0]).unwrap();
        }
    }
}

fn main_() -> Result<(), Box<dyn Error>> {
    let tmpdir = tempdir()?;
    let file_path = tmpdir.path().join("maple.reg");

    let reg_output = std::process::Command::new("reg")
        .args(&["export", MAPLESTORY_REG_KEY, file_path.to_str().unwrap()])
        .output()
        .expect("Failed to execute process");

    if !reg_output.status.success() {
        println!("레지스트리 추출이 실패하였습니다. `reg` 명령어 출력:");
        println!("{}", decode_maybe_euckr(reg_output.stderr));
        return Err("레지스트리 추출 실패")?;
    }

    let registry = decode_maybe_euckr(
        std::fs::read(file_path).map_err(|e| format!(".reg 파일 읽기 실패: {}", e))?,
    );

    let pass1 =
        prompt_password_stdout("비밀번호 입력: ").expect("패스워드를 콘솔에서 읽어올 수 없음");
    let pass2 =
        prompt_password_stdout("비밀번호 다시 입력: ").expect("패스워드를 콘솔에서 읽어올 수 없음");

    if pass1 != pass2 {
        return Err("두 비밀번호가 다릅니다.")?;
    }

    if pass1.len() < 6 {
        Err("비밀번호는 6자리 이상이어야 합니다.")?;
    }

    let encrypted = zandam::encrypt(&registry, &pass1);
    let template = Template::from(HTML_TEMPLATE);

    let wasm_base64 = base64::encode(ZANDAM_WASM);
    let enc_base64 = base64::encode(&encrypted);
    let args = hashmap! {
        "wasm" => wasm_base64.as_ref(),
        "encrypted" => enc_base64.as_ref(),
        "js" => ZANDAM_JS,
        "z" => "${z}",
        "e.src" => "${e.src}",
    };
    let out_html = template.fill_in(&args).to_string();

    std::fs::write("zandam.html", out_html)?;

    tmpdir.close()?;
    Ok(())
}
