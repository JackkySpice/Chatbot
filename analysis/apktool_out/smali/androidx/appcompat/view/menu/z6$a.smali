.class public Landroidx/appcompat/view/menu/z6$a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/os/IBinder$DeathRecipient;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/z6;->a(Landroidx/appcompat/view/menu/uj0;Landroid/os/IBinder;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic l:Landroid/os/IBinder;

.field public final synthetic m:Landroidx/appcompat/view/menu/uj0;

.field public final synthetic n:Landroidx/appcompat/view/menu/z6;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/z6;Landroid/os/IBinder;Landroidx/appcompat/view/menu/uj0;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/z6$a;->n:Landroidx/appcompat/view/menu/z6;

    iput-object p2, p0, Landroidx/appcompat/view/menu/z6$a;->l:Landroid/os/IBinder;

    iput-object p3, p0, Landroidx/appcompat/view/menu/z6$a;->m:Landroidx/appcompat/view/menu/uj0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public binderDied()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/z6$a;->l:Landroid/os/IBinder;

    const/4 v1, 0x0

    invoke-interface {v0, p0, v1}, Landroid/os/IBinder;->unlinkToDeath(Landroid/os/IBinder$DeathRecipient;I)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/z6$a;->n:Landroidx/appcompat/view/menu/z6;

    iget-object v1, p0, Landroidx/appcompat/view/menu/z6$a;->m:Landroidx/appcompat/view/menu/uj0;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/z6;->q(Landroidx/appcompat/view/menu/uj0;)V

    return-void
.end method
