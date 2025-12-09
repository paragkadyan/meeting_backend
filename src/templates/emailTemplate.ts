import fs from "fs";
import path from "path";

export function renderTemplate(templateName: string, variables: Record<string, string>) {
    const filePath = path.join(__dirname, "..", "templates", templateName);
    let template = fs.readFileSync(filePath, "utf-8");
    Object.keys(variables).forEach((key) => {
        const regex = new RegExp(`{{${key}}}`, "g");
        template = template.replace(regex, variables[key]);
    });

    // Use a CID reference for the logo so the sending code can attach it as an inline image.
    // This avoids embedding a large base64 data URI directly into the HTML (which can cause
    // mail clients like Gmail to clip or truncate messages).
    template = template.replace(/{{logo}}/g, `cid:fullLogo`);

    return template;
}

