.class public final Landroidx/appcompat/view/menu/fc2;
.super Landroid/content/BroadcastReceiver;
.source "SourceFile"


# instance fields
.field public final a:Landroidx/appcompat/view/menu/yw1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/yw1;)V
    .locals 0

    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/fc2;->a:Landroidx/appcompat/view/menu/yw1;

    return-void
.end method


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 2

    if-nez p2, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/fc2;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lt1;->L()Landroidx/appcompat/view/menu/ot1;

    move-result-object p1

    const-string p2, "App receiver called with null intent"

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    return-void

    :cond_0
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object p1

    if-nez p1, :cond_1

    iget-object p1, p0, Landroidx/appcompat/view/menu/fc2;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lt1;->L()Landroidx/appcompat/view/menu/ot1;

    move-result-object p1

    const-string p2, "App receiver called with null action"

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    return-void

    :cond_1
    const-string p2, "com.google.android.gms.measurement.TRIGGERS_AVAILABLE"

    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_2

    iget-object p1, p0, Landroidx/appcompat/view/menu/fc2;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lt1;->L()Landroidx/appcompat/view/menu/ot1;

    move-result-object p1

    const-string p2, "App receiver called with unknown action"

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    return-void

    :cond_2
    iget-object p1, p0, Landroidx/appcompat/view/menu/fc2;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-static {}, Landroidx/appcompat/view/menu/oc2;->a()Z

    move-result p2

    if-eqz p2, :cond_4

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yw1;->z()Landroidx/appcompat/view/menu/mf1;

    move-result-object p2

    sget-object v0, Landroidx/appcompat/view/menu/oi1;->M0:Landroidx/appcompat/view/menu/qs1;

    const/4 v1, 0x0

    invoke-virtual {p2, v1, v0}, Landroidx/appcompat/view/menu/mf1;->D(Ljava/lang/String;Landroidx/appcompat/view/menu/qs1;)Z

    move-result p2

    if-nez p2, :cond_3

    goto :goto_0

    :cond_3
    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object p2

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/lt1;->K()Landroidx/appcompat/view/menu/ot1;

    move-result-object p2

    const-string v0, "App receiver notified triggers are available"

    invoke-virtual {p2, v0}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yw1;->h()Landroidx/appcompat/view/menu/fw1;

    move-result-object p2

    new-instance v0, Landroidx/appcompat/view/menu/he2;

    invoke-direct {v0, p1}, Landroidx/appcompat/view/menu/he2;-><init>(Landroidx/appcompat/view/menu/yw1;)V

    invoke-virtual {p2, v0}, Landroidx/appcompat/view/menu/fw1;->D(Ljava/lang/Runnable;)V

    :cond_4
    :goto_0
    return-void
.end method
