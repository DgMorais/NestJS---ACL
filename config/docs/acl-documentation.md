# Explicação do `main.ts` e Funções Adicionais
---

## Explicação do `main.ts`

### Importações
``` typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
```
- **NestFactory:** Utilizado para criar uma instância da aplicação NestJS.
- **AppModule:** O módulo raiz da aplicação.
- **DocumentBuilder, SwaggerModule:** Ferramentas do Swagger para documentar a API.

### Função bootstrap
``` typescript
async function bootstrap() {
    const app = await NestFactory.create(AppModule);
```
- **NestFactory.create(AppModule):** Cria a aplicação a partir do módulo raiz (AppModule). A função é assíncrona, por isso usamos await.

### Configuração do Prefixo Global
``` typescript
app.setGlobalPrefix('api');
```
- **app.setGlobalPrefix('api'):** Define um prefixo global para todas as rotas da aplicação. Isso significa que todas as rotas começarão com /api.

### Configuração do Swagger
``` typescript
const config = new DocumentBuilder()
    .setTitle('Plataforma API')
    .setDescription('API para gerenciamento de usuários, roles, permissões e grupos')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
```
- **DocumentBuilder:** Constrói a configuração da documentação do Swagger.
  - **setTitle:** Define o título da documentação.
  - **setDescription:** Define a descrição da API.
  - **setVersion:** Define a versão da API.
  - **addBearerAuth:** Adiciona autenticação via token Bearer na documentação.
  - **build():** Constrói a configuração final.

``` typescript
const document = SwaggerModule.createDocument(app, config);
SwaggerModule.setup('api/docs', app, document);
```
- **SwaggerModule.createDocument(app, config):** Cria o documento do Swagger com a configuração definida.
- **SwaggerModule.setup('api/docs', app, document):** Configura a rota /api/docs para acessar a documentação da API.

### Inicialização do Servidor
``` typescript
    await app.listen(3000);
}
bootstrap();
```
- **await app.listen(3000):** Inicia o servidor da aplicação na porta 3000.
- **bootstrap():** Chama a função bootstrap para iniciar a aplicação.

## Resumo
O arquivo main.ts realiza as seguintes tarefas:
&emsp;**1.** Cria a aplicação NestJS a partir do módulo raiz.
&emsp;**2.** Define um prefixo global para as rotas.
&emsp;**3.** Configura a documentação da API usando o Swagger.
&emsp;**4.** Inicia o servidor na porta 3000.

---
## Funções Comuns no `main.ts`

&emsp; Pode se criar outras funções dentro do arquivo main.ts para adicionar configurações específicas ou inicializações necessárias. Abaixo estão algumas funções comuns e seus fins.

### Funções Comuns
**1. Configurações de Middleware**
- **Propósito:** Adicionar middlewares globais, como o corpo do parser ou middlewares de segurança.
- **Exemplo:**
  ``` typescript
    async function setupMiddlewares(app) {
        // Configurações de middleware aqui
        app.use(bodyParser.json());
        app.use(helmet());
    }
  ```

**2. Configurações de Segurança**
- **Propósito:** Configurar CORS (Cross-Origin Resource Sharing) ou outras políticas de segurança.
- **Exemplo:**
    ``` typescript
    async function setupSecurity(app) {
        app.enableCors({
            origin: ['http://example.com', 'http://another-domain.com'],
            methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
            credentials: true,
        });
    }
    ```
    
**3. Configurações de Internacionalização (i18n)**
- **Propósito:** Configurar suporte a múltiplos idiomas na aplicação.
- **Exemplo:**
    ``` typescript
    async function setupI18n(app) {
        // Configuração de internacionalização aqui
    }
    ```

**4. Serviços de Inicialização**
- **Propósito:** Executar tarefas iniciais como a configuração de um serviço ou a pré-carregamento de dados.
- **Exemplo:**
    ``` typescript
    async function initializeServices(app) {
        const someService = app.get(SomeService);
        await someService.initialize();
    }
    ```

**5. Configurações de Log**
- **Propósito:** Configurar logging global para a aplicação.
- **Exemplo:**
    ``` typescript
    async function setupLogging(app) {
        // Configuração de logging aqui
    }
    ```

### Integração no `main.ts`
&emsp; Pode se chamar essas funções dentro da função bootstrap para garantir que todas as configurações e inicializações ocorram antes de a aplicação começar a ouvir por requisições:
``` typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    // Configurar o prefixo global
    app.setGlobalPrefix('api');

    await setupMiddlewares(app);
    await setupSecurity(app);
    await setupI18n(app);
    await initializeServices(app);
    await setupLogging(app);

    const config = new DocumentBuilder()
        .setTitle('Plataforma API')
        .setDescription('API para gerenciamento de usuários, roles, permissões e grupos')
        .setVersion('1.0')
        .addBearerAuth()
        .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);

    await app.listen(3000);
}
bootstrap();

async function setupMiddlewares(app) {
    // Configurações de middleware aqui
    app.use(bodyParser.json());
    app.use(helmet());
}

async function setupSecurity(app) {
    app.enableCors({
        origin: ['http://example.com', 'http://another-domain.com'],
        methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
        credentials: true,
    });
}

async function setupI18n(app) {
    // Configuração de internacionalização aqui
}

async function initializeServices(app) {
    const someService = app.get(SomeService);
    await someService.initialize();
}

async function setupLogging(app) {
    // Configuração de logging aqui
}
```

## Resumo
&emsp; Adicionar funções ao `main.ts` é uma maneira de organizar e modularizar as configurações e inicializações necessárias para a sua aplicação. Funções comuns incluem configurações de middleware, segurança, internacionalização, inicialização de serviços e logging. Estas funções ajudam a manter o código limpo e separado por responsabilidade, tornando a aplicação mais fácil de manter e entender.

---

# Estrutura do `AppModule`
&emsp; É o módulo raiz da aplicação. O AppModule é responsável por configurar e importar todos os módulos necessários para a aplicação funcionar corretamente.

``` typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { RolesModule } from './roles/roles.module';
import { PermissionsModule } from './permissions/permissions.module';
import { GroupsModule } from './groups/groups.module';
import { User } from './users/entities/user.entity';
import { Role } from './roles/entities/role.entity';
import { Permission } from './permissions/entities/permission.entity';
import { Group } from './groups/entities/group.entity';
```
- **Module:** Decorador utilizado para definir um módulo em NestJS.
- **TypeOrmModule:** Módulo do TypeORM para integração com o banco de dados.
- **Módulo do TypeORM para integração com o banco de dados.** Módulos para gerenciamento de configurações.
- **UsersModule, AuthModule, RolesModule, PermissionsModule, GroupsModule:** Módulos específicos da aplicação.
- **User, Role, Permission, Group:** Entidades do TypeORM que representam as tabelas do banco de dados.

## Decorador `@Module`
``` typescript
@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
        }),
        TypeOrmModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) => ({
                type: 'mysql',
                host: configService.get<string>('DB_HOST'),
                port: configService.get<number>('DB_PORT'),
                username: configService.get<string>('DB_USERNAME'),
                password: configService.get<string>('DB_PASSWORD'),
                database: configService.get<string>('DB_NAME'),
                entities: [User, Role, Permission, Group],
                synchronize: true, // Não usar em produção, pode causar perda de dados
                charset: 'utf8mb4_general_ci',
            }),
        }),
        TypeOrmModule.forFeature([User, Role, Permission, Group]),
        UsersModule,
        AuthModule,
        RolesModule,
        PermissionsModule,
        GroupsModule,
    ],
})
export class AppModule { }
```
- **imports:** Lista de módulos que serão importados e utilizados dentro deste módulo.

### Configuração dos Módulos
- **ConfigModule**
    ``` typescript
    ConfigModule.forRoot({
        isGlobal: true,
    }),
    ```
    - **ConfigModule.forRoot:** Configura o módulo de configuração para ser utilizado globalmente na aplicação.

- **TypeOrmModule**
    ``` typescript
    TypeOrmModule.forRootAsync({
        imports: [ConfigModule],
        inject: [ConfigService],
        useFactory: (configService: ConfigService) => ({
            type: 'mysql',
            host: configService.get<string>('DB_HOST'),
            port: configService.get<number>('DB_PORT'),
            username: configService.get<string>('DB_USERNAME'),
            password: configService.get<string>('DB_PASSWORD'),
            database: configService.get<string>('DB_NAME'),
            entities: [User, Role, Permission, Group],
            synchronize: true, // Não usar em produção, pode causar perda de dados
            charset: 'utf8mb4_general_ci',
        }),
    }),
    ```
    - **TypeOrmModule.forRootAsync:** Configura a conexão com o banco de dados de forma assíncrona.
      - **imports:** Importa o ConfigModule para acessar as variáveis de configuração.
      - **inject:** Injeta o ConfigService para obter as variáveis de ambiente.
      - **useFactory:** Função que retorna a configuração do TypeORM utilizando as variáveis de configuração.

- **TypeOrmModule.forFeature**
    ``` typescript
    TypeOrmModule.forFeature([User, Role, Permission, Group]),
    ```
    - **TypeOrmModule.forFeature:** Importa as entidades do TypeORM que serão utilizadas pelos repositórios dentro dos módulos.

- **Módulos da Aplicação**
    ```
    UsersModule,
    AuthModule,
    RolesModule,
    PermissionsModule,
    GroupsModule,
    ```
    - **UsersModule, AuthModule, RolesModule, PermissionsModule, GroupsModule:** Importa os módulos específicos da aplicação que gerenciam usuários, autenticação, roles, permissões e grupos.

## Resumo
&emsp; O `AppModule` é o módulo raiz da aplicação NestJS. Ele configura e importa todos os módulos necessários, incluindo:

&emsp; **1. ConfigModule:** Para gerenciamento de configurações.
&emsp; **2. TypeOrmModule:** Para integração com o banco de dados.
&emsp; **3. UsersModule, AuthModule, RolesModule, PermissionsModule, GroupsModule:** Módulos específicos da aplicação.

&emsp; Ele também define as entidades que representam as tabelas no banco de dados e configura a conexão com o banco de dados utilizando variáveis de ambiente.

---

# Arquivo `auth.controller.ts`

### Importações
``` typescript
import { Controller, Request, Post, UseGuards, Body, Logger } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
```
- **Controller, Request, Post, UseGuards, Body, Logger:** Decorators e utilitários do NestJS para definir controladores, manipular requisições, definir rotas HTTP, aplicar guardas e logar mensagens.
- **AuthService:** Serviço de autenticação que contém a lógica para login e registro.
- **LocalAuthGuard, JwtAuthGuard:** Guardas que implementam a lógica de autenticação com diferentes estratégias (local e JWT).
- **RegisterDto, LoginDto:** Data Transfer Objects (DTOs) para validar os dados de registro e login.
- **ApiTags, ApiOperation, ApiResponse:** Decorators do Swagger para documentação da API.

### Decorators e Definição do Controlador
``` typescript
@ApiTags('auth')
@Controller('auth')
export class AuthController {
    private readonly logger = new Logger(AuthController.name);

    constructor(private readonly authService: AuthService) { }
```
- **@ApiTags('auth'):** Define a tag para agrupar as rotas de autenticação na documentação do Swagger.
- **@Controller('auth'):** Define o prefixo das rotas para este controlador (`/auth`).
- **logger:** Instância do Logger para registrar mensagens no contexto do controlador.
- **constructor:**Injeta o serviço de autenticação (`AuthService`) no controlador.

### Rota de Login
``` typescript
@UseGuards(LocalAuthGuard)
@Post('login')
@ApiOperation({ summary: 'Login do usuário' })
@ApiResponse({ status: 200, description: 'Login bem-sucedido' })
@ApiResponse({ status: 401, description: 'Credenciais inválidas' })
async login(@Body() loginDto: LoginDto, @Request() req: any) {
    return this.authService.login(req.user);
}
```
- **@UseGuards(LocalAuthGuard):** Aplica a guarda `LocalAuthGuard` à rota de login. Esta guarda usa a estratégia local para autenticar o usuário.
- **@Post('login'):** Define a rota `POST /auth/login`.
- **@ApiOperation, @ApiResponse:** Decorators do Swagger para documentar a operação e as respostas possíveis.
- **login:** Método que lida com a requisição de login. Recebe os dados do login através do `loginDto` e o objeto de requisição (`req`). Chama o método `login` do `AuthService`.

### Rota de Registro
``` typescript
@Post('register')
@ApiOperation({ summary: 'Registro de novo usuário' })
@ApiResponse({ status: 201, description: 'Usuário registrado com sucesso' })
@ApiResponse({ status: 400, description: 'Dados inválidos' })
async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
}
```
- **@Post('register'):** Define a rota `POST /auth/register`.
- **@ApiOperation, @ApiResponse:** Decorators do Swagger para documentar a operação e as respostas possíveis.
- **register:** Método que lida com a requisição de registro. Recebe os dados do registro através do `registerDto`. Chama o método `register` do `AuthService`

### Rota de Perfil
``` typescript
    @UseGuards(JwtAuthGuard)
    @Post('profile')
    @ApiOperation({ summary: 'Perfil do usuário' })
    @ApiResponse({ status: 200, description: 'Perfil do usuário retornado com sucesso' })
    @ApiResponse({ status: 401, description: 'Usuário não autorizado' })
    getProfile(@Request() req: any) {
        return req.user;
    }
}
```
- **@UseGuards(JwtAuthGuard):** Aplica a guarda `JwtAuthGuard` à rota de perfil. Esta guarda usa a estratégia JWT para autenticar o usuário.
- **@Post('profile'):** Define a rota `POST /auth/profile`.
- **@ApiOperation, @ApiResponse:** Decorators do Swagger para documentar a operação e as respostas possíveis.
- **getProfile:** Método que lida com a requisição de perfil. Retorna o usuário autenticado presente no objeto de requisição (`req.user`).

## Resumo
- **Controlador de Autenticação:** Define as rotas para login, registro e perfil de usuário.
- **Guards:** Aplicam estratégias de autenticação (LocalAuthGuard para login e JwtAuthGuard para perfil).
- **DTOs:** Validação dos dados de entrada (login e registro).
- **Swagger:** Documentação da API para cada rota.

---

# Arquivo `auth.module.ts`
&emsp; O arquivo `auth.module.ts` organiza tudo relacionado à autenticação em um único lugar.
``` typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { UsersModule } from '../users/users.module';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
    imports: [
        UsersModule,
        PassportModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: { expiresIn: '60m' },
            }),
        }),
    ],
    providers: [AuthService, LocalStrategy, JwtStrategy],
    controllers: [AuthController],
})
export class AuthModule { }
```
**1. @Module:** Diz ao NestJS que esta classe é um módulo.
**2. imports:** Define os módulos que este módulo precisa.
**3. providers:** Define os serviços e estratégias de autenticação que este módulo fornece.
**4. controllers:** Define o controlador que lida com as requisições HTTP relacionadas à autenticação.

### Explicação Detalhada
- **Imports**
  ``` typescript
  import { Module } from '@nestjs/common';
  import { JwtModule } from '@nestjs/jwt';
  import { PassportModule } from '@nestjs/passport';
  import { AuthService } from './auth.service';
  import { AuthController } from './auth.controller';
  import { JwtStrategy } from './strategies/jwt.strategy';
  import { LocalStrategy } from './strategies/local.strategy';
  import { UsersModule } from '../users/users.module';
  import { ConfigModule, ConfigService } from '@nestjs/config';
  ```
  - **Module:** Importa a classe `Module` do NestJS.
  - **JwtModule:** Módulo para trabalhar com JWT (JSON Web Tokens).
  - **PassportModule:** Módulo para trabalhar com estratégias de autenticação usando Passport.
  - **AuthService, AuthController:** Serviço e controlador de autenticação.
  - **JwtStrategy, LocalStrategy:** Estratégias de autenticação (JWT e Local).
  - **UsersModule:** Importa o módulo de usuários para acessar os serviços de usuários.
  - **ConfigModule, ConfigService:** Módulo e serviço para trabalhar com variáveis de configuração.

- **Configuração do Módulo**
``` typescript
@Module({
    imports: [
        UsersModule,
        PassportModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: { expiresIn: '60m' },
            }),
        }),
    ],
    providers: [AuthService, LocalStrategy, JwtStrategy],
    controllers: [AuthController],
})
export class AuthModule { }
```
1. **imports**
   - **UsersModule:** Importa o módulo de usuários para poder usar o `UsersService`.
   - **PassportModule:** Importa o módulo do Passport para usar estratégias de autenticação.
   - **JwtModule.registerAsync:** Configura o módulo JWT de forma assíncrona usando o `ConfigService` para obter a chave secreta (`JWT_SECRET`) e definir as opções de assinatura (`signOptions`).
2. **providers**
   - **AuthService:** Serviço que contém a lógica de autenticação.
   - **LocalStrategy:** Estratégia de autenticação local (usuário/senha).
   - **JwtStrategy:** Estratégia de autenticação JWT (token).
3. **controllers**
   - **AuthController:** Controlador que lida com as requisições HTTP relacionadas à autenticação.

### Como Funciona a Configuração Assíncrona
&emsp; A configuração assíncrona permite que o módulo JWT seja configurado dinamicamente com base nas variáveis de configuração. Isso é útil para garantir que as configurações sensíveis, como a chave secreta JWT, sejam carregadas de forma segura.
``` typescript
JwtModule.registerAsync({
    imports: [ConfigModule],
    inject: [ConfigService],
    useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '60m' },
    }),
}),
```
**1. registerAsync:** Permite que o módulo JWT seja configurado de forma assíncrona.
**2. imports:** Importa o ConfigModule para acessar as variáveis de configuração.
**3. inject:** Injeta o ConfigService para obter a chave secreta (JWT_SECRET).
**4. useFactory:** Função que retorna as configurações do JWT.

## Resumo
- **@Module:** Define a classe como um módulo NestJS.
- **imports:** Importa outros módulos necessários (`UsersModule`, `PassportModule`, `JwtModule`).
- **providers:** Define os provedores (serviços e estratégias de autenticação).
- **controllers:** Define os controladores que lidam com requisições HTTP.
- **Configuração Assíncrona do JWT:** Usa o `ConfigService` para obter a chave secreta e configura o módulo JWT dinamicamente.

&emsp; Essa configuração permite que o `AuthModule` forneça serviços de autenticação robustos e seguros, integrando-se com os serviços de usuários e utilizando estratégias de autenticação modernas como JWT e Passport.

# Arquivo `auth.service.ts`

O `AuthService` lida com a lógica de autenticação, como validação de usuário, login e registro.

- **Imports**
  ``` typescript
  import { Injectable, Logger } from '@nestjs/common';
  import { UsersService } from '../users/users.service';
  import { JwtService } from '@nestjs/jwt';
  import * as bcrypt from 'bcrypt';
  import { RegisterDto } from './dto/register.dto';
  import { ConfigService } from '@nestjs/config';
  ```
  - **Injectable:** Diz que essa classe pode ser injetada em outros lugares.
  - **Logger:** Para registrar mensagens de depuração.
  - **UsersService:** Serviço que lida com os dados dos usuários.
  - **JwtService:** Serviço para trabalhar com tokens JWT.
  - **bcrypt:** Biblioteca para hashing de senhas.
  - **RegisterDto:** Objeto de transferência de dados para registro de usuários.
  - **ConfigService:** Serviço para acessar variáveis de configuração.

- **Definição do AuthService**
  ``` typescript
  @Injectable()
  export class AuthService {
      private readonly logger = new Logger(AuthService.name);

      constructor(
          private usersService: UsersService,
          private jwtService: JwtService,
          private readonly configService: ConfigService,
      ) { }
  ```
  - **@Injectable():** Marca a classe como um serviço que pode ser injetado.
  - **Logger:** Para registrar mensagens de depuração.
  - **Constructor:** Pede `UsersService`, `JwtService` e `ConfigService` ao NestJS, e ele os entrega.

- **validateUser()**
  ``` typescript
  async validateUser(email: string, password: string): Promise<any> {
      this.logger.debug(`Validating user with email: ${email}`);
      this.logger.debug(`Provided password: ${password}`);

      try {
          const user = await this.usersService.findOneByEmailWithPassword(email);
          this.logger.debug(`Stored hashed password: ${user.password}`);

          const passwordMatches = await bcrypt.compare(password, user.password);
          this.logger.debug(`Password matches: ${passwordMatches}`);

          if (user && passwordMatches) {
              this.logger.debug(`User validated: ${email}`);
              const { password, ...result } = user;
              return result;
          }
      } catch (error) {
          this.logger.error(`Error validating user: ${error.message}`);
      }
      this.logger.debug(`Invalid credentials for email: ${email}`);
      return null;
  }
  ```
  - **validateUser:** Valida o usuário verificando o email e a senha.
    - Procura o usuário pelo email.
    - Compara a senha fornecida com a senha armazenada (usando `bcrypt`).
    - Se as credenciais forem válidas, retorna o usuário (sem a senha).

- **login()**
  ```
  async login(user: any) {
      const payload = { email: user.email, sub: user.id };
      return {
          access_token: this.jwtService.sign(payload),
      };
  }
  ```
  - **login:** Gera um token JWT para o usuário.
    - Cria um `payload` com o email do usuário e seu ID.
    - Usa o `JwtService` para assinar o token e retorna o token.

- **register()**
  ``` typescript
        async register(registerDto: RegisterDto) {
            const salt = await bcrypt.genSalt(10);

            const hashedPassword = await bcrypt.hash(registerDto.password, 10);
            this.logger.debug(`${hashedPassword}`);
            const user = await this.usersService.create({
                ...registerDto,
                password: hashedPassword,
            });
            this.logger.debug(`User registered with email: ${registerDto.email} and hashed password.`);
            this.logger.debug(`User registered with pass: ${registerDto.password} and hashed password.`);
            return user;
        }
    }
  ```
  - **register:** Registra um novo usuário.
    - Gera um `salt` e um `hashedPassword` para a senha.
    - Cria um novo usuário com a senha hash e os outros dados do `registerDto`.
    - Usa o `UsersService` para salvar o usuário no banco de dados.

## Resumo
- **validateUser:** Verifica se o email e a senha do usuário são válidos.
- **login:** Gera um token JWT para o usuário.
- **register:** Registra um novo usuário, armazenando a senha de forma segura.

&emsp; Esses métodos ajudam a gerenciar a autenticação de usuários de maneira segura e eficiente.

# Arquivo `auth/decorators/roles.decorator.ts`

&emsp; O arquivo `roles.decorator.ts` define um decorador personalizado Roles que é usado para marcar rotas ou métodos específicos com os papéis (roles) necessários para acessá-los.

1. **Imports**
   ``` typescript
   import { SetMetadata } from '@nestjs/common';
   ```
   - **SetMetadata:** Uma função fornecida pelo NestJS para definir metadados personalizados em rotas ou métodos.

2. **Definição do Decorador**
   ``` typescript
   export const Roles = (...roles: string[]) => SetMetadata('roles', roles);
   ```
   - **Roles:** O nome do decorador personalizado.
   - **(...roles: string[]):** Aceita um número variável de strings que representam os papéis necessários.
   - **SetMetadata('roles', roles):** Define um metadado chamado roles com os valores fornecidos.

## Como Usar o Decorador `Roles`
&emsp; O decorador `Roles` é usado para marcar métodos ou controladores com os papéis necessários. Em conjunto com guardas (guards), ele pode ser usado para restringir o acesso a determinadas rotas com base nos papéis do usuário.

### Exemplo de Uso
`users.controller.ts:`
``` typescript
import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { Roles } from '../auth/decorators/roles.decorator';
import { RolesGuard } from '../auth/guards/roles.guard';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard) // Aplica as guardas JWT e de papéis
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @Post()
    @Roles('admin') // Somente usuários com o papel 'admin' podem acessar essa rota
    create(@Body() createUserDto: CreateUserDto) {
        return this.usersService.create(createUserDto);
    }

    @Get()
    @Roles('admin', 'user') // Somente usuários com os papéis 'admin' ou 'user' podem acessar essa rota
    findAll() {
        return this.usersService.findAll();
    }
}
```

## Guardas (Guards) para Verificação de Papéis
&emsp; Para que o decorador `Roles` funcione, precisamos de uma guarda que verifique os papéis do usuário.
`roles.guard.ts:`
``` typescript
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtAuthGuard } from './jwt-auth.guard';

@Injectable()
export class RolesGuard extends JwtAuthGuard implements CanActivate {
    constructor(private reflector: Reflector) {
        super();
    }

    canActivate(context: ExecutionContext): boolean {
        const roles = this.reflector.get<string[]>('roles', context.getHandler());
        if (!roles) {
            return true;
        }
        const request = context.switchToHttp().getRequest();
        const user = request.user;
        return roles.some(role => user.roles?.includes(role));
    }
}
```
#### Explicação Simples
- **Reflector:** Usado para acessar os metadados definidos pelo decorador `Roles`.
- **canActivate:** Método que verifica se o usuário tem os papéis necessários.
  - Obtém os papéis necessários da rota.
  - Verifica se o usuário tem algum dos papéis necessários.

## Resumo
- **Decorador `Roles`:** Define metadados sobre os papéis necessários para acessar uma rota.
 - **Guarda `RolesGuard`:** Verifica se o usuário tem os papéis necessários antes de permitir o acesso à rota.

&emsp; Essa combinação ajuda a restringir o acesso a determinadas rotas com base nos papéis do usuário, tornando a aplicação mais segura e organizada.

# Arquivo `auth/dto/login.dto.ts`

O arquivo `login.dto.ts` define um objeto de transferência de dados (DTO) para a operação de login. Os DTOs são usados para validar e tipar os dados que são enviados em uma requisição HTTP.

1. **Imports**
   ``` typescript
   import { ApiProperty } from '@nestjs/swagger';
   import { IsString, IsNotEmpty, IsEmail } from 'class-validator';
   ```
   - **ApiProperty:** Usado para documentar a propriedade da classe no Swagger.
   - **IsString, IsNotEmpty, IsEmail:** Decoradores do `class-validator` para validar os dados.

2. **Definição da Classe LoginDto**
   ``` typescript
   export class LoginDto {
       @ApiProperty({ example: 'joao_doe@example.com', description: 'Email do usuário' })
       @IsEmail()
       @IsNotEmpty()
       readonly email: string;

       @ApiProperty({ example: 'senha123', description: 'Senha do usuário' })
       @IsString()
       @IsNotEmpty()
       readonly password: string;
   }
   ```
   - **email:** O email do usuário.
      - **@ApiProperty:** Documenta a propriedade para o Swagger, especificando um exemplo e uma descrição.
      - **@IsEmail:** Valida se o valor é um email válido.
      - **@IsNotEmpty:** Valida se o valor não está vazio.
   - **password:** A senha do usuário.
     - **@ApiProperty:** Documenta a propriedade para o Swagger, especificando um exemplo e uma descrição.
     - **@IsString:** Valida se o valor é uma string.
     - **@IsNotEmpty:** Valida se o valor não está vazio.

## Uso do LoginDto no AuthController
&emsp; O `LoginDto` é utilizado no controlador de autenticação para validar os dados da requisição de login.

`auth.controller.ts:`
``` typescript
import { Controller, Request, Post, UseGuards, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { LoginDto } from './dto/login.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @UseGuards(LocalAuthGuard)
    @Post('login')
    @ApiOperation({ summary: 'Login do usuário' })
    @ApiResponse({ status: 200, description: 'Login bem-sucedido' })
    @ApiResponse({ status: 401, description: 'Credenciais inválidas' })
    async login(@Body() loginDto: LoginDto, @Request() req: any) {
        return this.authService.login(req.user);
    }
}
```

### Explicação do AuthController
1. **Rota de Login**
   ``` typescript
   @UseGuards(LocalAuthGuard)
   @Post('login')
   @ApiOperation({ summary: 'Login do usuário' })
   @ApiResponse({ status: 200, description: 'Login bem-sucedido' })
   @ApiResponse({ status: 401, description: 'Credenciais inválidas' })
   async login(@Body() loginDto: LoginDto, @Request() req: any) {
       return this.authService.login(req.user);
   }
   ```

   - **@UseGuards(LocalAuthGuard):** Aplica a guarda de autenticação local para verificar as credenciais.
   - **@Post('login'):** Define a rota POST /auth/login.
   - **@ApiOperation, @ApiResponse:** Documenta a operação e as respostas possíveis no Swagger.
   - **login(@Body() loginDto: LoginDto, @Request() req: any):**
     - **@Body() loginDto:** LoginDto: Extrai e valida os dados do corpo da requisição usando o LoginDto.
     - **@Request() req:** any: Acessa o objeto de requisição para obter o usuário autenticado.

## Resumo
- **LoginDto:** Define a estrutura e valida os dados para a operação de login.
- **Propriedades:**
  - **email:** Deve ser um email válido e não vazio.
  - **password:** Deve ser uma string e não vazia.
- **Uso no AuthController:** Valida os dados da requisição de login antes de processá-los.

&emsp; O `LoginDto` ajuda a garantir que os dados enviados na requisição de login estejam no formato correto e sejam válidos, facilitando a implementação de uma lógica de autenticação segura e robusta.

# Arquivo `auth/dto/register.dto.ts`

&emsp; O arquivo `register.dto.ts` define um objeto de transferência de dados (DTO) para a operação de registro. Os DTOs são usados para validar e tipar os dados que são enviados em uma requisição HTTP.

1. **Imports**
   ``` typescript
   import { ApiProperty } from '@nestjs/swagger';
   import { IsString, IsNotEmpty, IsEmail, MinLength } from 'class-validator';
   ```
   - **ApiProperty:** Usado para documentar a propriedade da classe no Swagger.
   - **IsString, IsNotEmpty, IsEmail, MinLength:** Decoradores do class-validator para validar os dados.

2. **Definição da Classe RegisterDto**
    ``` typescript
    export class RegisterDto {
        @ApiProperty({ example: 'João Doe', description: 'Nome do usuário' })
        @IsString()
        @IsNotEmpty()
        readonly name: string;

        @ApiProperty({ example: 'joao_doe@example.com', description: 'Email do usuário' })
        @IsEmail()
        @IsNotEmpty()
        readonly email: string;

        @ApiProperty({ example: 'senha123', description: 'Senha do usuário' })
        @IsString()
        @MinLength(6)
        @IsNotEmpty()
        readonly password: string;
    }
    ```
    - **name:** O nome do usuário.
      - **@ApiProperty:** Documenta a propriedade para o Swagger, especificando um exemplo e uma descrição.
      - **@IsString:** Valida se o valor é uma string.
      - **@IsNotEmpty:** Valida se o valor não está vazio.
   - **email:** O email do usuário.
     - **@ApiProperty:** Documenta a propriedade para o Swagger, especificando um exemplo e uma descrição.
     - **@IsEmail:** Valida se o valor é um email válido.
     - **@IsNotEmpty:** Valida se o valor não está vazio.
   - **password:** A senha do usuário.
     - **@ApiProperty:** Documenta a propriedade para o Swagger, especificando um exemplo e uma descrição.
     - **@IsString:** Valida se o valor é uma string.
     - **@MinLength(6):** Valida se a senha tem pelo menos 6 caracteres.
     - **@IsNotEmpty:** Valida se o valor não está vazio.

## Uso do RegisterDto no AuthController
&emsp; O `RegisterDto` é utilizado no controlador de autenticação para validar os dados da requisição de registro.

`auth.controller.ts:`
``` typescript
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('register')
    @ApiOperation({ summary: 'Registro de novo usuário' })
    @ApiResponse({ status: 201, description: 'Usuário registrado com sucesso' })
    @ApiResponse({ status: 400, description: 'Dados inválidos' })
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }
}
```

### Explicação do AuthController
1. **Rota de Registro**
   ``` typescript
   @Post('register')
   @ApiOperation({ summary: 'Registro de novo usuário' })
   @ApiResponse({ status: 201, description: 'Usuário registrado com sucesso' })
   @ApiResponse({ status: 400, description: 'Dados inválidos' })
   async register(@Body() registerDto: RegisterDto) {
       return this.authService.register(registerDto);
   }
   ```
   - **@Post('register'):** Define a rota `POST /auth/register`.
   - **@ApiOperation, @ApiResponse:** Documenta a operação e as respostas possíveis no Swagger.
   - **register(@Body() registerDto: RegisterDto):**
     - **@Body() registerDto:** RegisterDto: Extrai e valida os dados do corpo da requisição usando o `RegisterDto`.

## Resumo

- **RegisterDto:** Define a estrutura e valida os dados para a operação de registro.
- **Propriedades:**
  - **name:** Deve ser uma string e não vazia.
  - **email:** Deve ser um email válido e não vazio.
  - **password:** Deve ser uma string, ter pelo menos 6 caracteres e não estar vazia.
- **Uso no AuthController:** Valida os dados da requisição de registro antes de processá-los.

&emsp; O `RegisterDto` ajuda a garantir que os dados enviados na requisição de registro estejam no formato correto e sejam válidos, facilitando a implementação de uma lógica de registro segura e robusta.

# Arquivo `auth/guards/jwt-auth.guards.ts`

O `JwtAuthGuard` é uma guarda (guard) personalizada que usa a estratégia JWT (JSON Web Token) para proteger rotas.

1. **Imports:**
    ``` typescript
    import { Injectable } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    ```

   - **Injectable:** Decorador que marca a classe como injetável pelo sistema de injeção de dependências do NestJS.
   - **AuthGuard:** Classe fornecida pelo `@nestjs/passport` que implementa uma guarda de autenticação.

## Definição da Classe JwtAuthGuard
``` typescript
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
```

- **@Injectable():** Marca a classe `JwtAuthGuard` como um serviço que pode ser injetado em outros lugares.
- **AuthGuard('jwt'):** Estende a classe `AuthGuard` e passa a string `'jwt'` para usar a estratégia JWT definida anteriormente.

### Como Funciona
- **AuthGuard:** O `AuthGuard` é uma guarda genérica que pode ser configurada para usar diferentes estratégias de autenticação. No caso do `JwtAuthGuard`, ele está configurado para usar a estratégia JWT.
- **JWT Strategy:** A estratégia JWT verifica se o token JWT presente no cabeçalho da requisição é válido. Se for, a requisição é autorizada e o usuário pode acessar a rota protegida.

## Uso do JwtAuthGuard no AuthController
O `JwtAuthGuard` é utilizado no controlador de autenticação para proteger rotas que requerem autenticação JWT.

`auth.controller.ts:`
``` typescript
import { Controller, Request, Post, UseGuards, Get } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(LocalAuthGuard)
    @Post('login')
    @ApiOperation({ summary: 'Login do usuário' })
    @ApiResponse({ status: 200, description: 'Login bem-sucedido' })
    @ApiResponse({ status: 401, description: 'Credenciais inválidas' })
    async login(@Request() req: any) {
        return this.authService.login(req.user);
    }

    @Post('register')
    @ApiOperation({ summary: 'Registro de novo usuário' })
    @ApiResponse({ status: 201, description: 'Usuário registrado com sucesso' })
    @ApiResponse({ status: 400, description: 'Dados inválidos' })
    async register(@Request() req: any, @Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @UseGuards(JwtAuthGuard)
    @Get('profile')
    @ApiOperation({ summary: 'Perfil do usuário' })
    @ApiResponse({ status: 200, description: 'Perfil do usuário retornado com sucesso' })
    @ApiResponse({ status: 401, description: 'Usuário não autorizado' })
    getProfile(@Request() req: any) {
        return req.user;
    }
}
```

1. **Rota de Perfil Protegida**
    ``` typescript
    @UseGuards(JwtAuthGuard)
    @Get('profile')
    @ApiOperation({ summary: 'Perfil do usuário' })
    @ApiResponse({ status: 200, description: 'Perfil do usuário retornado com sucesso' })
    @ApiResponse({ status: 401, description: 'Usuário não autorizado' })
    getProfile(@Request() req: any) {
        return req.user;
    }
    ```

   - **@UseGuards(JwtAuthGuard):** Aplica a guarda `JwtAuthGuard` à rota, protegendo-a com a estratégia JWT.
   - **@Get('profile'):** Define a rota `GET /auth/profile`.
   - **@ApiOperation, @ApiResponse:** Documenta a operação e as respostas possíveis no Swagger.
   - **getProfile(@Request() req: any):** Retorna o perfil do usuário autenticado, que está disponível no objeto de requisição.

## Resumo
- **JwtAuthGuard:** Uma guarda personalizada que usa a estratégia JWT para proteger rotas.
- **AuthGuard:** Classe genérica que implementa a lógica de guarda usando diferentes estratégias de autenticação.
- **Uso no AuthController:** Protege rotas que requerem autenticação JWT, como a rota de perfil do usuário.

&emsp; O JwtAuthGuard ajuda a garantir que apenas usuários autenticados com um token JWT válido possam acessar determinadas rotas, aumentando a segurança da aplicação.

## Exemplos de guards
### 1. Guarda JWT (JSON Web Token)
A guarda JWT é usada para proteger rotas que requerem um token JWT válido.

`jwt-auth.guard.ts`
``` typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
```

### 2. Guarda Local (Username e Password)
A guarda Local é usada para autenticar usuários com username e senha.

`local-auth.guard.ts`
``` typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
```

### 3. Guarda API Key
A guarda API Key é usada para autenticar usuários com uma chave de API.

api-key-auth.guard.ts3. Guarda API Key
A guarda API Key é usada para autenticar usuários com uma chave de API.

`api-key-auth.guard.ts`
``` typescript
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class ApiKeyAuthGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const apiKey = request.headers['api-key'];

    // Substitua 'your-api-key' pela sua chave de API
    return apiKey === 'your-api-key';
  }
}
```

### 4. Guarda Roles (Papéis)
A guarda Roles é usada para proteger rotas baseadas nos papéis do usuário.

`roles.guard.ts`
``` typescript
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!roles) {
      return true;
    }
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    return roles.some(role => user.roles?.includes(role));
  }
}
```

### 5. Guarda OAuth (Open Authentication)
A guarda OAuth é usada para autenticar usuários com OAuth.

`oauth-auth.guard.ts`
``` typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class OAuthAuthGuard extends AuthGuard('oauth') {}
```

## Exemplos de Uso das Guardas no Controlador

Exemplo: `auth.controller.ts:`
``` typescript
import { Controller, Get, Post, UseGuards, Request, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { ApiKeyAuthGuard } from './guards/api-key-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { OAuthAuthGuard } from './guards/oauth-auth.guard';
import { Roles } from './decorators/roles.decorator';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req: any) {
    return this.authService.login(req.user);
  }

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req: any) {
    return req.user;
  }

  @UseGuards(ApiKeyAuthGuard)
  @Get('data')
  getData(@Request() req: any) {
    return { data: 'This is protected by API Key' };
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @Get('admin')
  getAdminData(@Request() req: any) {
    return { data: 'This is protected for admins only' };
  }

  @UseGuards(OAuthAuthGuard)
  @Get('oauth/callback')
  oauthCallback(@Request() req: any) {
    return this.authService.oauthLogin(req.user);
  }
}
```

**1. login:** Usa `LocalAuthGuard` para autenticação com username e senha.
**2. register:** Não usa guarda, disponível publicamente.
**3. getProfile:** Usa `JwtAuthGuard` para proteger a rota com JWT.
**4. getData:** Usa `ApiKeyAuthGuard` para proteger a rota com chave de API.
**5. getAdminData:** Usa `JwtAuthGuard` e `RolesGuard` para proteger a rota para administradores.
**6. oauthCallback:** Usa `OAuthAuthGuard` para autenticação com OAuth.

## Resumo
- **Guarda JWT:** Protege rotas com token JWT.
- **Guarda Local:** Autentica com username e senha.
- **Guarda API Key:** Protege rotas com chave de API.
- **Guarda Roles:** Protege rotas baseadas nos papéis do usuário.
- **Guarda OAuth:** Autentica com OAuth.

&emsp; Esses exemplos demonstram como usar diferentes guardas para implementar diversas estratégias de autenticação, tornando sua aplicação mais segura e flexível.

# Arquivo `auth/guards/local-auth.guards.ts`

O `LocalAuthGuard` é uma guarda (guard) personalizada que usa a estratégia local (username e senha) para autenticar usuários.

1. **Imports:**
    ``` typescript
    import { Injectable } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    ```

   - **Injectable:** Decorador que marca a classe como injetável pelo sistema de injeção de dependências do NestJS.
   - **AuthGuard:** Classe fornecida pelo `@nestjs/passport` que implementa uma guarda de autenticação.

## Definição da Classe LocalAuthGuard
``` typescript
@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
```

- **@Injectable():** Marca a classe `LocalAuthGuard` como um serviço que pode ser injetado em outros lugares.
- **AuthGuard('local'):** Estende a classe `AuthGuard` e passa a string `'local'` para usar a estratégia local definida anteriormente.

## Como Funciona
- **AuthGuard:** O AuthGuard é uma guarda genérica que pode ser configurada para usar diferentes estratégias de autenticação. No caso do LocalAuthGuard, ele está configurado para usar a estratégia local.
- **Local Strategy:** A estratégia local verifica o username e a senha fornecidos pelo usuário. Se forem válidos, a requisição é autorizada e o usuário pode acessar a rota protegida.

### Uso do LocalAuthGuard no AuthController

O `LocalAuthGuard` é utilizado no controlador de autenticação para proteger a rota de login, garantindo que apenas usuários com credenciais válidas possam acessar essa rota.

``` typescript
import { Controller, Post, UseGuards, Body, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { LoginDto } from './dto/login.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(LocalAuthGuard)
    @Post('login')
    @ApiOperation({ summary: 'Login do usuário' })
    @ApiResponse({ status: 200, description: 'Login bem-sucedido' })
    @ApiResponse({ status: 401, description: 'Credenciais inválidas' })
    async login(@Body() loginDto: LoginDto, @Request() req: any) {
        return this.authService.login(req.user);
    }

    // Outros métodos...
}
```

1. **Rota de Login:**
    ``` typescript
    @UseGuards(LocalAuthGuard)
    @Post('login')
    @ApiOperation({ summary: 'Login do usuário' })
    @ApiResponse({ status: 200, description: 'Login bem-sucedido' })
    @ApiResponse({ status: 401, description: 'Credenciais inválidas' })
    async login(@Body() loginDto: LoginDto, @Request() req: any) {
        return this.authService.login(req.user);
    }
    ```
    - **@UseGuards(LocalAuthGuard):** Aplica a guarda LocalAuthGuard à rota, protegendo-a com a estratégia local.
    - **@Post('login'):** Define a rota POST /auth/login.
    - **@ApiOperation, @ApiResponse:** Documenta a operação e as respostas possíveis no Swagger.
    - **login(@Body() loginDto: LoginDto, @Request() req: any):**
      - **@Body() loginDto: LoginDto:** Extrai e valida os dados do corpo da requisição usando o LoginDto.
      - **@Request() req: any:** Acessa o objeto de requisição para obter o usuário autenticado.

## Resumo
- **LocalAuthGuard:** Uma guarda personalizada que usa a estratégia local para autenticar usuários.
- **AuthGuard:** Classe genérica que implementa a lógica de guarda usando diferentes estratégias de autenticação.
- **Uso no AuthController:** Protege a rota de login, garantindo que apenas usuários com credenciais válidas possam acessar.

&emsp; O LocalAuthGuard ajuda a garantir que apenas usuários com username e senha válidos possam acessar a rota de login, aumentando a segurança da aplicação.

# Arquivo `auth/guards/roles.guards.ts`

O `RolesGuard` é uma guarda (guard) personalizada que verifica se o usuário possui os papéis (roles) necessários para acessar uma rota.

**Imports**
``` typescript
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
```

- **Injectable:** Decorador que marca a classe como injetável pelo sistema de injeção de dependências do NestJS.
- **CanActivate:** Interface que define o método canActivate para determinar se a requisição pode prosseguir.
- **ExecutionContext:** Objeto que fornece detalhes sobre o contexto da execução atual.
- **Reflector:** Classe usada para acessar os metadados definidos pelos decoradores.
- **JwtService:** Serviço para trabalhar com tokens JWT.

## Definição da Classe RolesGuard
``` typescript
@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private reflector: Reflector, private jwtService: JwtService) { }

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>('roles', [
            context.getHandler(),
            context.getClass(),
        ]);
        if (!requiredRoles) {
            return true;
        }
        const request = context.switchToHttp().getRequest();
        const token = request.headers.authorization.split(' ')[1];
        const user = this.jwtService.verify(token);

        return requiredRoles.some((role) => user.roles?.includes(role));
    }
}
```
- **@Injectable():** Marca a classe `RolesGuard` como um serviço que pode ser injetado em outros lugares.
- **constructor(private reflector: Reflector, private jwtService: JwtService):** Injeta o `Reflector` e o JwtService na classe.
- **canActivate(context: ExecutionContext):** Método que determina se a requisição pode prosseguir com base nos papéis do usuário.

## Como Funciona
- **Reflector:** O `Reflector` é usado para obter os metadados dos papéis (roles) definidos nos controladores e métodos.
- **JwtService:** O `JwtService` é usado para verificar o token JWT e obter os dados do usuário.
- **canActivate:**
  - Obtém os papéis necessários (`requiredRoles`) usando o `Reflector`.
  - Se não houver papéis necessários, a guarda permite o acesso (`return true`).
  - Obtém a requisição HTTP e extrai o token JWT do cabeçalho.
  - Verifica o token JWT para obter os dados do usuário.
  - Verifica se o usuário possui pelo menos um dos papéis necessários (`requiredRoles`).

## Uso do RolesGuard no Controlador
O `RolesGuard` é utilizado nos controladores para proteger rotas com base nos papéis do usuário.

``` typescript
import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('admin')
    @Get('admin')
    getAdminData(@Request() req: any) {
        return { data: 'This is protected for admins only' };
    }
}
```

1. **Rota Protegida por Papéis**
    ``` typescript
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('admin')
    @Get('admin')
    getAdminData(@Request() req: any) {
        return { data: 'This is protected for admins only' };
    }
    ```
    - **@UseGuards(JwtAuthGuard, RolesGuard):** Aplica as guardas JwtAuthGuard e RolesGuard à rota, protegendo-a com autenticação JWT e verificação de papéis.
    - **@Roles('admin'):** Define que a rota requer o papel admin.
    - **@Get('admin'):** Define a rota GET /auth/admin.
    - **getAdminData(@Request() req: any):** Retorna os dados para administradores.

## Resumo
- **RolesGuard:** Uma guarda personalizada que verifica se o usuário possui os papéis necessários para acessar uma rota.
- **Reflector:** Usado para acessar os metadados dos papéis definidos nos controladores e métodos.
- **JwtService:** Verifica o token JWT e obtém os dados do usuário.
- **Uso no AuthController:** Protege rotas que requerem papéis específicos.

&emsp; O `RolesGuard` ajuda a garantir que apenas usuários com os papéis necessários possam acessar determinadas rotas, aumentando a segurança e a flexibilidade da aplicação.

# Arquivo `groups/groups.controller.ts`