.class public final Landroidx/appcompat/view/menu/vc1;
.super Landroidx/appcompat/view/menu/wc1;
.source "SourceFile"


# instance fields
.field public final synthetic a:Landroid/content/Intent;

.field public final synthetic b:Landroidx/appcompat/view/menu/v80;


# direct methods
.method public constructor <init>(Landroid/content/Intent;Landroidx/appcompat/view/menu/v80;I)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/vc1;->a:Landroid/content/Intent;

    iput-object p2, p0, Landroidx/appcompat/view/menu/vc1;->b:Landroidx/appcompat/view/menu/v80;

    invoke-direct {p0}, Landroidx/appcompat/view/menu/wc1;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/vc1;->a:Landroid/content/Intent;

    if-eqz v0, :cond_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/vc1;->b:Landroidx/appcompat/view/menu/v80;

    const/4 v2, 0x2

    invoke-interface {v1, v0, v2}, Landroidx/appcompat/view/menu/v80;->startActivityForResult(Landroid/content/Intent;I)V

    :cond_0
    return-void
.end method
