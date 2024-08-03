import { DataSource, DataSourceOptions } from 'typeorm';
import * as dotenv from 'dotenv';
import * as path from 'path';

// Resolver o caminho do arquivo .env com base no diretório atual
const envPath = path.resolve(__dirname, '../../config/.env');
dotenv.config({ path: envPath });

const requiredEnvVars = ['DB_HOST', 'DB_PORT', 'DB_USERNAME', 'DB_PASSWORD', 'DB_NAME'];

requiredEnvVars.forEach((varName) => {
    if (!process.env[varName]) {
        throw new Error(`Env variable ${varName} is required`);
    }
});

const dataSourceOptions: DataSourceOptions = {
    type: 'mysql',
    host: process.env.DB_HOST,
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306,
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    entities: [path.join(__dirname, '/../src/**/*.entity{.ts,.js}')],
    migrations: [path.join(__dirname, '/../migrations/*{.ts,.js}')],
    synchronize: false, // Desativar sincronização automática
    charset: 'utf8mb4_general_ci',
    logging: true, // Ativar logging para ajudar no debug
};

const AppDataSource = new DataSource(dataSourceOptions);

export default AppDataSource;
