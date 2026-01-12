.class public final Landroidx/appcompat/view/menu/o42;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/ya2;

.field public final synthetic n:Z

.field public final synthetic o:Landroidx/appcompat/view/menu/r92;

.field public final synthetic p:Landroidx/appcompat/view/menu/d42;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/d42;Landroidx/appcompat/view/menu/ya2;ZLandroidx/appcompat/view/menu/r92;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/o42;->p:Landroidx/appcompat/view/menu/d42;

    iput-object p2, p0, Landroidx/appcompat/view/menu/o42;->m:Landroidx/appcompat/view/menu/ya2;

    iput-boolean p3, p0, Landroidx/appcompat/view/menu/o42;->n:Z

    iput-object p4, p0, Landroidx/appcompat/view/menu/o42;->o:Landroidx/appcompat/view/menu/r92;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/o42;->p:Landroidx/appcompat/view/menu/d42;

    invoke-static {v0}, Landroidx/appcompat/view/menu/d42;->B(Landroidx/appcompat/view/menu/d42;)Landroidx/appcompat/view/menu/ts1;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/o42;->p:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "Discarding data. Failed to set user property"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    return-void

    :cond_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/o42;->m:Landroidx/appcompat/view/menu/ya2;

    invoke-static {v1}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, p0, Landroidx/appcompat/view/menu/o42;->p:Landroidx/appcompat/view/menu/d42;

    iget-boolean v2, p0, Landroidx/appcompat/view/menu/o42;->n:Z

    if-eqz v2, :cond_1

    const/4 v2, 0x0

    goto :goto_0

    :cond_1
    iget-object v2, p0, Landroidx/appcompat/view/menu/o42;->o:Landroidx/appcompat/view/menu/r92;

    :goto_0
    iget-object v3, p0, Landroidx/appcompat/view/menu/o42;->m:Landroidx/appcompat/view/menu/ya2;

    invoke-virtual {v1, v0, v2, v3}, Landroidx/appcompat/view/menu/d42;->K(Landroidx/appcompat/view/menu/ts1;Landroidx/appcompat/view/menu/r;Landroidx/appcompat/view/menu/ya2;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/o42;->p:Landroidx/appcompat/view/menu/d42;

    invoke-static {v0}, Landroidx/appcompat/view/menu/d42;->m0(Landroidx/appcompat/view/menu/d42;)V

    return-void
.end method
