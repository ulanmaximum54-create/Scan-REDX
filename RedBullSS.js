// =========================================
// KellerSS Analyzer v1.0
// iOS Privacy Report Scanner
// Scriptable
// =========================================


const DATABASE = {

    suspiciousWords: [
        "vpn",
        "proxy",
        "inject",
        "loader",
        "cheat",
        "hack",
        "macro",
        "autoclick",
        "frida",
        "tweak",
        "cydia",
        "substrate"
    ],

    sideload: [
        "altstore",
        "sideloadly",
        "scarlet",
        "trollstore",
        "esign",
        "enterprise",
        "developer"
    ]

};



async function selectReport(){

    let file =
    await DocumentPicker.openFile(
        ["public.data"]
    );

    if(!file)
        throw "Файл не выбран";


    let fm =
    FileManager.iCloud();


    return fm.readString(file);

}



function analyze(data){


    let text =
    data.toLowerCase();


    let result = {

        risk:0,
        warnings:[],
        domains:[]

    };



    let domains =
    text.match(
        /[a-z0-9.-]+\.[a-z]{2,}/g
    );


    if(domains){

        result.domains =
        [...new Set(domains)];

    }



    for(let domain of result.domains){

        for(let word of DATABASE.suspiciousWords){

            if(domain.includes(word)){

                result.warnings.push(
                    "Подозрительный домен: "
                    + domain
                );

                result.risk +=5;

            }

        }

    }



    for(let word of DATABASE.suspiciousWords){

        if(text.includes(word)){

            result.warnings.push(
                "Найдено: "
                + word
            );

            result.risk +=5;

        }

    }



    for(let word of DATABASE.sideload){

        if(text.includes(word)){

            result.warnings.push(
                "Sideload признак: "
                + word
            );

            result.risk +=15;

        }

    }



    if(text.includes("freefire")
    ||
    text.includes("garena")){

        result.warnings.push(
            "Free Fire найден"
        );

    }



    if(result.risk > 100)
        result.risk = 100;



    return result;

}



function createReport(r){


return `

==========================

KELLERSS ANALYZER v1.0

==========================


RISK SCORE:
${r.risk}/100


STATUS:
${
r.risk < 30
?
"LOW"
:
r.risk < 70
?
"MEDIUM"
:
"HIGH"
}



FINDINGS:

${
r.warnings.length
?
r.warnings.join("\n")
:
"Ничего подозрительного"
}



DOMAINS:

${r.domains.slice(0,50).join("\n")}



==========================

`;

}



async function main(){


try{


let data =
await selectReport();


let result =
analyze(data);


let report =
createReport(result);



let fm =
FileManager.iCloud();


let path =
fm.joinPath(
fm.documentsDirectory(),
"KellerSS_Report.txt"
);



fm.writeString(
path,
report
);



QuickLook.present(path);


}

catch(e){

let a =
new Alert();

a.title =
"Ошибка";

a.message =
e.toString();

await a.present();

}


}



await main();
