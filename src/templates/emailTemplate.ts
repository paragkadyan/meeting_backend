import fs from "fs";
import path from "path";

export function renderTemplate(templateName: string, variables: Record<string, string>) {
    const filePath = path.join(__dirname, "..", "templates", templateName);
    let template = fs.readFileSync(filePath, "utf-8");

    Object.keys(variables).forEach((key) => {
        const regex = new RegExp(`{{${key}}}`, "g");
        template = template.replace(regex, variables[key]);
    });

    return template;
}
