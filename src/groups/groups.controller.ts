import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common';
import { GroupsService } from './groups.service';
import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@ApiTags('groups')
@Controller('groups')
@UseGuards(JwtAuthGuard, RolesGuard)
export class GroupsController {
    constructor(private readonly groupsService: GroupsService) { }

    @Post()
    @Roles('admin') // Somente administradores podem criar grupos
    @ApiOperation({ summary: 'Criar um novo grupo' })
    @ApiResponse({ status: 201, description: 'O grupo foi criado com sucesso.' })
    @ApiResponse({ status: 403, description: 'Proibido.' })
    create(@Body() createGroupDto: CreateGroupDto) {
        return this.groupsService.create(createGroupDto);
    }

    @Get()
    @ApiOperation({ summary: 'Obter todos os grupos' })
    @ApiResponse({ status: 200, description: 'Retorna todos os grupos.' })
    findAll() {
        return this.groupsService.findAll();
    }

    @Get(':id')
    @ApiOperation({ summary: 'Obter um grupo pelo ID' })
    @ApiResponse({ status: 200, description: 'Retorna um grupo pelo ID.' })
    @ApiResponse({ status: 404, description: 'Grupo não encontrado.' })
    findOne(@Param('id') id: string) {
        return this.groupsService.findOne(+id);
    }

    @Patch(':id')
    @Roles('admin') // Somente administradores podem atualizar grupos
    @ApiOperation({ summary: 'Atualizar um grupo' })
    @ApiResponse({ status: 200, description: 'O grupo foi atualizado com sucesso.' })
    @ApiResponse({ status: 404, description: 'Grupo não encontrado.' })
    update(@Param('id') id: string, @Body() updateGroupDto: UpdateGroupDto) {
        return this.groupsService.update(+id, updateGroupDto);
    }

    @Delete(':id')
    @Roles('admin') // Somente administradores podem excluir grupos
    @ApiOperation({ summary: 'Excluir um grupo' })
    @ApiResponse({ status: 200, description: 'O grupo foi excluído com sucesso.' })
    @ApiResponse({ status: 404, description: 'Grupo não encontrado.' })
    remove(@Param('id') id: string) {
        return this.groupsService.remove(+id);
    }
}
