.class public final Landroidx/appcompat/view/menu/l52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Z

.field public final synthetic n:Landroidx/appcompat/view/menu/ya2;

.field public final synthetic o:Z

.field public final synthetic p:Landroidx/appcompat/view/menu/ki1;

.field public final synthetic q:Ljava/lang/String;

.field public final synthetic r:Landroidx/appcompat/view/menu/d42;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/d42;ZLandroidx/appcompat/view/menu/ya2;ZLandroidx/appcompat/view/menu/ki1;Ljava/lang/String;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/l52;->r:Landroidx/appcompat/view/menu/d42;

    iput-boolean p2, p0, Landroidx/appcompat/view/menu/l52;->m:Z

    iput-object p3, p0, Landroidx/appcompat/view/menu/l52;->n:Landroidx/appcompat/view/menu/ya2;

    iput-boolean p4, p0, Landroidx/appcompat/view/menu/l52;->o:Z

    iput-object p5, p0, Landroidx/appcompat/view/menu/l52;->p:Landroidx/appcompat/view/menu/ki1;

    iput-object p6, p0, Landroidx/appcompat/view/menu/l52;->q:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/l52;->r:Landroidx/appcompat/view/menu/d42;

    invoke-static {v0}, Landroidx/appcompat/view/menu/d42;->B(Landroidx/appcompat/view/menu/d42;)Landroidx/appcompat/view/menu/ts1;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/l52;->r:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "Discarding data. Failed to send event to service"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    return-void

    :cond_0
    iget-boolean v1, p0, Landroidx/appcompat/view/menu/l52;->m:Z

    if-eqz v1, :cond_2

    iget-object v1, p0, Landroidx/appcompat/view/menu/l52;->n:Landroidx/appcompat/view/menu/ya2;

    invoke-static {v1}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, p0, Landroidx/appcompat/view/menu/l52;->r:Landroidx/appcompat/view/menu/d42;

    iget-boolean v2, p0, Landroidx/appcompat/view/menu/l52;->o:Z

    if-eqz v2, :cond_1

    const/4 v2, 0x0

    goto :goto_0

    :cond_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/l52;->p:Landroidx/appcompat/view/menu/ki1;

    :goto_0
    iget-object v3, p0, Landroidx/appcompat/view/menu/l52;->n:Landroidx/appcompat/view/menu/ya2;

    invoke-virtual {v1, v0, v2, v3}, Landroidx/appcompat/view/menu/d42;->K(Landroidx/appcompat/view/menu/ts1;Landroidx/appcompat/view/menu/r;Landroidx/appcompat/view/menu/ya2;)V

    goto :goto_2

    :cond_2
    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/l52;->q:Ljava/lang/String;

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_3

    iget-object v1, p0, Landroidx/appcompat/view/menu/l52;->n:Landroidx/appcompat/view/menu/ya2;

    invoke-static {v1}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, p0, Landroidx/appcompat/view/menu/l52;->p:Landroidx/appcompat/view/menu/ki1;

    iget-object v2, p0, Landroidx/appcompat/view/menu/l52;->n:Landroidx/appcompat/view/menu/ya2;

    invoke-interface {v0, v1, v2}, Landroidx/appcompat/view/menu/ts1;->g0(Landroidx/appcompat/view/menu/ki1;Landroidx/appcompat/view/menu/ya2;)V

    goto :goto_2

    :catch_0
    move-exception v0

    goto :goto_1

    :cond_3
    iget-object v1, p0, Landroidx/appcompat/view/menu/l52;->p:Landroidx/appcompat/view/menu/ki1;

    iget-object v2, p0, Landroidx/appcompat/view/menu/l52;->q:Ljava/lang/String;

    iget-object v3, p0, Landroidx/appcompat/view/menu/l52;->r:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v3

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/lt1;->O()Ljava/lang/String;

    move-result-object v3

    invoke-interface {v0, v1, v2, v3}, Landroidx/appcompat/view/menu/ts1;->A(Landroidx/appcompat/view/menu/ki1;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :goto_1
    iget-object v1, p0, Landroidx/appcompat/view/menu/l52;->r:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v1

    const-string v2, "Failed to send event to the service"

    invoke-virtual {v1, v2, v0}, Landroidx/appcompat/view/menu/ot1;->b(Ljava/lang/String;Ljava/lang/Object;)V

    :goto_2
    iget-object v0, p0, Landroidx/appcompat/view/menu/l52;->r:Landroidx/appcompat/view/menu/d42;

    invoke-static {v0}, Landroidx/appcompat/view/menu/d42;->m0(Landroidx/appcompat/view/menu/d42;)V

    return-void
.end method
