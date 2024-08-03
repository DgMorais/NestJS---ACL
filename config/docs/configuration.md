# Gerador JWT SECRET KEY
`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`

# Criar uma migração vazia
`npx typeorm migration:create src/migrations/AdjustPasswordColumnToText`
- #### Executar uma migração
    - `npx typeorm migration:run -d ormconfig.js`
- #### Exemplo de migração:
    ```
    import { MigrationInterface, QueryRunner } from 'typeorm';

    export class AdjustPasswordColumnToText1616789123456 implements MigrationInterface {
        public async up(queryRunner: QueryRunner): Promise<void> {
            await queryRunner.query(`ALTER TABLE user MODIFY COLUMN password TEXT;`);
        }

        public async down(queryRunner: QueryRunner): Promise<void> {
            await queryRunner.query(`ALTER TABLE user MODIFY COLUMN password VARCHAR(255);`);
        }
    }
    ```
