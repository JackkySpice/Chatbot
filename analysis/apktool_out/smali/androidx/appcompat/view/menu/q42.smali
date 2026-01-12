.class public final Landroidx/appcompat/view/menu/q42;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/ya2;

.field public final synthetic n:Landroidx/appcompat/view/menu/dm1;

.field public final synthetic o:Landroidx/appcompat/view/menu/d42;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/d42;Landroidx/appcompat/view/menu/ya2;Landroidx/appcompat/view/menu/dm1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    iput-object p2, p0, Landroidx/appcompat/view/menu/q42;->m:Landroidx/appcompat/view/menu/ya2;

    iput-object p3, p0, Landroidx/appcompat/view/menu/q42;->n:Landroidx/appcompat/view/menu/dm1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    const-string v0, "Failed to get app instance id"

    const/4 v1, 0x0

    :try_start_0
    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v2

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/pu1;->J()Landroidx/appcompat/view/menu/hz1;

    move-result-object v2

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/hz1;->y()Z

    move-result v2

    if-nez v2, :cond_0

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v2

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lt1;->M()Landroidx/appcompat/view/menu/ot1;

    move-result-object v2

    const-string v3, "Analytics storage consent denied; will not get app instance id"

    invoke-virtual {v2, v3}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/dr1;->r()Landroidx/appcompat/view/menu/zz1;

    move-result-object v2

    invoke-virtual {v2, v1}, Landroidx/appcompat/view/menu/zz1;->T(Ljava/lang/String;)V

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v2

    iget-object v2, v2, Landroidx/appcompat/view/menu/pu1;->g:Landroidx/appcompat/view/menu/cv1;

    invoke-virtual {v2, v1}, Landroidx/appcompat/view/menu/cv1;->b(Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v0

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->n:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v0, v2, v1}, Landroidx/appcompat/view/menu/t92;->R(Landroidx/appcompat/view/menu/dm1;Ljava/lang/String;)V

    return-void

    :catchall_0
    move-exception v0

    goto :goto_1

    :catch_0
    move-exception v2

    goto :goto_0

    :cond_0
    :try_start_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-static {v2}, Landroidx/appcompat/view/menu/d42;->B(Landroidx/appcompat/view/menu/d42;)Landroidx/appcompat/view/menu/ts1;

    move-result-object v2

    if-nez v2, :cond_1

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v2

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v2

    invoke-virtual {v2, v0}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v0

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->n:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v0, v2, v1}, Landroidx/appcompat/view/menu/t92;->R(Landroidx/appcompat/view/menu/dm1;Ljava/lang/String;)V

    return-void

    :cond_1
    :try_start_2
    iget-object v3, p0, Landroidx/appcompat/view/menu/q42;->m:Landroidx/appcompat/view/menu/ya2;

    invoke-static {v3}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v3, p0, Landroidx/appcompat/view/menu/q42;->m:Landroidx/appcompat/view/menu/ya2;

    invoke-interface {v2, v3}, Landroidx/appcompat/view/menu/ts1;->P1(Landroidx/appcompat/view/menu/ya2;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_2

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/dr1;->r()Landroidx/appcompat/view/menu/zz1;

    move-result-object v2

    invoke-virtual {v2, v1}, Landroidx/appcompat/view/menu/zz1;->T(Ljava/lang/String;)V

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v2

    iget-object v2, v2, Landroidx/appcompat/view/menu/pu1;->g:Landroidx/appcompat/view/menu/cv1;

    invoke-virtual {v2, v1}, Landroidx/appcompat/view/menu/cv1;->b(Ljava/lang/String;)V

    :cond_2
    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-static {v2}, Landroidx/appcompat/view/menu/d42;->m0(Landroidx/appcompat/view/menu/d42;)V
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v0

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->n:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v0, v2, v1}, Landroidx/appcompat/view/menu/t92;->R(Landroidx/appcompat/view/menu/dm1;Ljava/lang/String;)V

    return-void

    :goto_0
    :try_start_3
    iget-object v3, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v3

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v3

    invoke-virtual {v3, v0, v2}, Landroidx/appcompat/view/menu/ot1;->b(Ljava/lang/String;Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v0

    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->n:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v0, v2, v1}, Landroidx/appcompat/view/menu/t92;->R(Landroidx/appcompat/view/menu/dm1;Ljava/lang/String;)V

    return-void

    :goto_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/q42;->o:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v2

    iget-object v3, p0, Landroidx/appcompat/view/menu/q42;->n:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v2, v3, v1}, Landroidx/appcompat/view/menu/t92;->R(Landroidx/appcompat/view/menu/dm1;Ljava/lang/String;)V

    throw v0
.end method
