.class public final synthetic Landroidx/appcompat/view/menu/l02;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public synthetic m:Landroidx/appcompat/view/menu/zz1;

.field public synthetic n:Landroid/os/Bundle;

.field public synthetic o:J


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/zz1;Landroid/os/Bundle;J)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/l02;->m:Landroidx/appcompat/view/menu/zz1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/l02;->n:Landroid/os/Bundle;

    iput-wide p3, p0, Landroidx/appcompat/view/menu/l02;->o:J

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    iget-object v0, p0, Landroidx/appcompat/view/menu/l02;->m:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, p0, Landroidx/appcompat/view/menu/l02;->n:Landroid/os/Bundle;

    iget-wide v2, p0, Landroidx/appcompat/view/menu/l02;->o:J

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/dr1;->p()Landroidx/appcompat/view/menu/vs1;

    move-result-object v4

    invoke-virtual {v4}, Landroidx/appcompat/view/menu/vs1;->G()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x0

    invoke-virtual {v0, v1, v4, v2, v3}, Landroidx/appcompat/view/menu/zz1;->G(Landroid/os/Bundle;IJ)V

    return-void

    :cond_0
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->M()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "Using developer consent only; google app id found"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    return-void
.end method
