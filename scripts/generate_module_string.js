#!/usr/bin/env node

const fs = require('fs');
const zlib = require('zlib');

function embedModule(moduleName) {
    const filePath = `modules_expanded/${moduleName}.js`;
    const cFilePath = 'microscript/ILibDuktape_Polyfills.c';
    
    if (!fs.existsSync(filePath)) {
        console.error(`Error: File ${filePath} not found`);
        process.exit(1);
    }
    
    if (!fs.existsSync(cFilePath)) {
        console.error(`Error: C file ${cFilePath} not found`);
        process.exit(1);
    }
    
    console.log(`Embedding module: ${moduleName}`);
    
    // Читаем файл модуля
    const data = fs.readFileSync(filePath, 'utf8');
    console.log(`- Module size: ${data.length} bytes`);
    
    // Сжимаем данные с помощью deflate (как в MeshAgent)
    const compressed = zlib.deflateSync(Buffer.from(data));
    const base64Data = compressed.toString('base64');
    console.log(`- Compressed size: ${compressed.length} bytes`);
    
    // Получаем timestamp файла
    const stat = fs.statSync(filePath);
    const timestamp = new Date(stat.mtime).toISOString().replace(/[:\-]/g, '').replace(/\..+/, '');
    
    // Генерируем строку C кода
    let cCode;
    if (base64Data.length > 8000) {
        // Для больших модулей используем memcpy_s (как в оригинальном code-utils)
        const varName = '_' + moduleName.replace(/-/g, '');
        cCode = `\n\tchar *${varName} = ILibMemory_Allocate(${base64Data.length + 1}, 0, NULL, NULL);`;
        
        let offset = 0;
        while (offset < base64Data.length) {
            const chunk = base64Data.substring(offset, offset + 16000);
            cCode += `\n\tmemcpy_s(${varName} + ${offset}, ${base64Data.length - offset}, "${chunk}", ${chunk.length});`;
            offset += chunk.length;
        }
        
        cCode += `\n\tILibDuktape_AddCompressedModuleEx(ctx, "${moduleName}", ${varName}, "${timestamp}");`;
        cCode += `\n\tfree(${varName});`;
    } else {
        // Для небольших модулей используем простой вызов
        cCode = `\tduk_peval_string_noresult(ctx, "addCompressedModule('${moduleName}', Buffer.from('${base64Data}', 'base64'), '${timestamp}');");`;
    }
    
    // Читаем C файл
    const cFileContent = fs.readFileSync(cFilePath, 'utf8');
    
    // Находим секцию для встраивания
    const beginMarker = '// {{ BEGIN AUTO-GENERATED BODY';
    const endMarker = '// }} END OF AUTO-GENERATED BODY';
    
    const beginIndex = cFileContent.indexOf(beginMarker);
    const endIndex = cFileContent.indexOf(endMarker);
    
    if (beginIndex === -1 || endIndex === -1) {
        console.error('Error: Could not find AUTO-GENERATED BODY markers in C file');
        process.exit(1);
    }
    
    // Проверяем, не встроен ли уже этот модуль
    const existingModulePattern = new RegExp(`addCompressedModule\\('${moduleName}'`);
    const bodySection = cFileContent.substring(beginIndex, endIndex);
    
    if (existingModulePattern.test(bodySection)) {
        console.log(`- Module '${moduleName}' is already embedded, replacing...`);
        // Удаляем старую версию модуля
        const modulePattern = new RegExp(`\\s*duk_peval_string_noresult\\(ctx, "addCompressedModule\\('${moduleName}'[^;]+;\\);\\s*`, 'g');
        const cleanedContent = cFileContent.replace(modulePattern, '');
        
        // Создаем новое содержимое
        const beforeSection = cleanedContent.substring(0, cleanedContent.indexOf(beginMarker) + beginMarker.length);
        const afterSection = cleanedContent.substring(cleanedContent.indexOf(endMarker));
        const newContent = beforeSection + '\n' + cCode + '\n\t' + afterSection;
        
        fs.writeFileSync(cFilePath, newContent);
    } else {
        console.log(`- Adding new module '${moduleName}'...`);
        // Добавляем новый модуль, сохраняя существующее содержимое
        const beforeSection = cFileContent.substring(0, endIndex);
        const afterSection = cFileContent.substring(endIndex);
        
        const newContent = beforeSection + '\t' + cCode + '\n' + afterSection;
        fs.writeFileSync(cFilePath, newContent);
    }
    
    console.log('✅ Module successfully embedded!');
    console.log('');
    console.log('Next steps:');
    console.log('1. Recompile the agent: make macos ARCHID=29');
    console.log('2. Test the agent to verify the module is available');
    
    return true;
}

// Проверяем аргументы командной строки
const moduleName = process.argv[2] || 'win-terminal';

console.log('MeshAgent Module Embedder');
console.log('='.repeat(50));

embedModule(moduleName);
