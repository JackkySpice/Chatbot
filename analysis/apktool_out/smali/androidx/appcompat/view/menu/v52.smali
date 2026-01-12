.class public final Landroidx/appcompat/view/menu/v52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Ljava/lang/String;

.field public final synthetic n:Ljava/lang/String;

.field public final synthetic o:Landroidx/appcompat/view/menu/ya2;

.field public final synthetic p:Landroidx/appcompat/view/menu/dm1;

.field public final synthetic q:Landroidx/appcompat/view/menu/d42;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/d42;Ljava/lang/String;Ljava/lang/String;Landroidx/appcompat/view/menu/ya2;Landroidx/appcompat/view/menu/dm1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    iput-object p2, p0, Landroidx/appcompat/view/menu/v52;->m:Ljava/lang/String;

    iput-object p3, p0, Landroidx/appcompat/view/menu/v52;->n:Ljava/lang/String;

    iput-object p4, p0, Landroidx/appcompat/view/menu/v52;->o:Landroidx/appcompat/view/menu/ya2;

    iput-object p5, p0, Landroidx/appcompat/view/menu/v52;->p:Landroidx/appcompat/view/menu/dm1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 6

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    invoke-static {v1}, Landroidx/appcompat/view/menu/d42;->B(Landroidx/appcompat/view/menu/d42;)Landroidx/appcompat/view/menu/ts1;

    move-result-object v1

    if-nez v1, :cond_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v1

    const-string v2, "Failed to get conditional properties; not connected to service"

    iget-object v3, p0, Landroidx/appcompat/view/menu/v52;->m:Ljava/lang/String;

    iget-object v4, p0, Landroidx/appcompat/view/menu/v52;->n:Ljava/lang/String;

    invoke-virtual {v1, v2, v3, v4}, Landroidx/appcompat/view/menu/ot1;->c(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/v52;->p:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v1, v2, v0}, Landroidx/appcompat/view/menu/t92;->S(Landroidx/appcompat/view/menu/dm1;Ljava/util/ArrayList;)V

    return-void

    :catchall_0
    move-exception v1

    goto :goto_1

    :catch_0
    move-exception v1

    goto :goto_0

    :cond_0
    :try_start_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/v52;->o:Landroidx/appcompat/view/menu/ya2;

    invoke-static {v2}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v2, p0, Landroidx/appcompat/view/menu/v52;->m:Ljava/lang/String;

    iget-object v3, p0, Landroidx/appcompat/view/menu/v52;->n:Ljava/lang/String;

    iget-object v4, p0, Landroidx/appcompat/view/menu/v52;->o:Landroidx/appcompat/view/menu/ya2;

    invoke-interface {v1, v2, v3, v4}, Landroidx/appcompat/view/menu/ts1;->o0(Ljava/lang/String;Ljava/lang/String;Landroidx/appcompat/view/menu/ya2;)Ljava/util/List;

    move-result-object v1

    invoke-static {v1}, Landroidx/appcompat/view/menu/t92;->t0(Ljava/util/List;)Ljava/util/ArrayList;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    invoke-static {v1}, Landroidx/appcompat/view/menu/d42;->m0(Landroidx/appcompat/view/menu/d42;)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/v52;->p:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v1, v2, v0}, Landroidx/appcompat/view/menu/t92;->S(Landroidx/appcompat/view/menu/dm1;Ljava/util/ArrayList;)V

    return-void

    :goto_0
    :try_start_2
    iget-object v2, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v2

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v2

    const-string v3, "Failed to get conditional properties; remote exception"

    iget-object v4, p0, Landroidx/appcompat/view/menu/v52;->m:Ljava/lang/String;

    iget-object v5, p0, Landroidx/appcompat/view/menu/v52;->n:Ljava/lang/String;

    invoke-virtual {v2, v3, v4, v5, v1}, Landroidx/appcompat/view/menu/ot1;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/v52;->p:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v1, v2, v0}, Landroidx/appcompat/view/menu/t92;->S(Landroidx/appcompat/view/menu/dm1;Ljava/util/ArrayList;)V

    return-void

    :goto_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/v52;->q:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v2

    iget-object v3, p0, Landroidx/appcompat/view/menu/v52;->p:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v2, v3, v0}, Landroidx/appcompat/view/menu/t92;->S(Landroidx/appcompat/view/menu/dm1;Ljava/util/ArrayList;)V

    throw v1
.end method
