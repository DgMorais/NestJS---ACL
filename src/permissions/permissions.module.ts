import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PermissionsService } from './permissions.service';
import { PermissionsController } from './permissions.controller';
import { Permission } from './entities/permission.entity';
import { AuthModule } from '../auth/auth.module'; // Importar AuthModule

@Module({
    imports: [
        TypeOrmModule.forFeature([Permission]),
        forwardRef(() => AuthModule), // Adicionar AuthModule
    ],
    controllers: [PermissionsController],
    providers: [PermissionsService],
})
export class PermissionsModule { }
