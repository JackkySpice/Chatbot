.class public Landroidx/appcompat/view/menu/tl$a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/tl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/tl;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/tl;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/tl$a;->m:Landroidx/appcompat/view/menu/tl;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/tl$a;->m:Landroidx/appcompat/view/menu/tl;

    invoke-static {v0}, Landroidx/appcompat/view/menu/tl;->g1(Landroidx/appcompat/view/menu/tl;)Landroid/content/DialogInterface$OnDismissListener;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/tl$a;->m:Landroidx/appcompat/view/menu/tl;

    invoke-static {v1}, Landroidx/appcompat/view/menu/tl;->f1(Landroidx/appcompat/view/menu/tl;)Landroid/app/Dialog;

    move-result-object v1

    invoke-interface {v0, v1}, Landroid/content/DialogInterface$OnDismissListener;->onDismiss(Landroid/content/DialogInterface;)V

    return-void
.end method
